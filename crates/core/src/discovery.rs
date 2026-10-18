use crate::*;
use base64::Engine;
use oxc_allocator::Allocator;
use oxc_parser::Parser;
use oxc_span::SourceType;
use scraper::{Html, Selector};
use std::collections::BTreeMap;
use url::Url;

#[derive(Debug)]
pub struct HtmlDiscovery {
    pub base: String,
    pub scripts: Vec<String>,
    pub inline: Vec<Artifact>,
    pub links: Vec<String>,
    pub imports: BTreeMap<String, String>,
}

pub fn classify(location: &str, bytes: &[u8], content_type: &str) -> ArtifactKind {
    let path = location
        .split(['?', '#'])
        .next()
        .unwrap_or(location)
        .to_lowercase();
    let start = String::from_utf8_lossy(&bytes[..bytes.len().min(1024)]);
    if content_type.contains("html")
        || start.trim_start().starts_with("<!DOCTYPE")
        || start.trim_start().starts_with("<html")
    {
        return ArtifactKind::Html;
    }
    if path.ends_with(".map") || path.ends_with(".maps") {
        return ArtifactKind::SourceMap;
    }
    if [".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx"]
        .iter()
        .any(|e| path.ends_with(e))
        || content_type.contains("javascript")
        || content_type.contains("typescript")
    {
        return ArtifactKind::Script;
    }
    if start.trim_start().starts_with('{')
        && serde_json::from_slice::<serde_json::Value>(bytes)
            .ok()
            .is_some_and(|v| {
                v["version"] == 3 && (v.get("sources").is_some() || v.get("sections").is_some())
            })
    {
        return ArtifactKind::SourceMap;
    }
    if content_type.contains("json") {
        ArtifactKind::Json
    } else {
        ArtifactKind::Text
    }
}

pub fn resolve(base: &str, reference: &str) -> Option<String> {
    let url = Url::parse(reference)
        .or_else(|_| Url::parse(base)?.join(reference))
        .ok()?;
    matches!(url.scheme(), "http" | "https" | "file" | "data").then(|| url.to_string())
}

pub fn html(artifact: &Artifact) -> HtmlDiscovery {
    let document = Html::parse_document(&String::from_utf8_lossy(&artifact.content));
    let select = |s: &str| Selector::parse(s).expect("static CSS selector");
    let base = document
        .select(&select("base[href]"))
        .next()
        .and_then(|e| resolve(&artifact.location, e.attr("href")?))
        .unwrap_or_else(|| artifact.location.clone());
    let mut out = HtmlDiscovery {
        base: base.clone(),
        scripts: vec![],
        inline: vec![],
        links: vec![],
        imports: BTreeMap::new(),
    };
    for (index, script) in document.select(&select("script")).enumerate() {
        let kind = script.attr("type").unwrap_or("");
        if kind == "importmap" {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&script.inner_html())
                && let Some(imports) = json.get("imports").and_then(|v| v.as_object())
            {
                for (k, v) in imports {
                    if let Some(resolved) = v.as_str().and_then(|s| resolve(&base, s)) {
                        out.imports.insert(k.clone(), resolved);
                    }
                }
            }
            continue;
        }
        if !kind.is_empty()
            && ![
                "module",
                "text/javascript",
                "application/javascript",
                "text/typescript",
            ]
            .contains(&kind)
        {
            continue;
        }
        if let Some(src) = script.attr("src") {
            if let Some(url) = resolve(&base, src) {
                out.scripts.push(url);
            }
        } else {
            let content = script.inner_html();
            if !content.trim().is_empty() {
                out.inline.push(Artifact::new(
                    format!("{}#inline-{index}.js", artifact.location),
                    ArtifactKind::Script,
                    content.into_bytes(),
                    "html_inline".into(),
                ));
            }
        }
    }
    for node in document.select(&select("link[href]")) {
        if node.attr("rel").is_some_and(|v| {
            v.split_whitespace().any(|r| {
                r == "modulepreload" || r == "preload" && node.attr("as") == Some("script")
            })
        }) && let Some(u) = node.attr("href").and_then(|s| resolve(&base, s))
        {
            out.scripts.push(u);
        }
    }
    for node in document.select(&select("a[href]")) {
        if let Some(u) = node.attr("href").and_then(|s| resolve(&base, s)) {
            out.links.push(u);
        }
    }
    out
}

pub fn map_reference(artifact: &Artifact) -> Option<String> {
    for key in ["sourcemap", "x-sourcemap"] {
        if let Some(value) = artifact
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
            .map(|(_, v)| v)
        {
            return Some(value.clone());
        }
    }
    let text = std::str::from_utf8(&artifact.content).ok()?;
    let allocator = Allocator::default();
    let parsed = Parser::new(&allocator, text, SourceType::mjs()).parse();
    let mut found = None;
    for comment in &parsed.program.comments {
        let comment = comment
            .content_span()
            .source_text(text)
            .trim()
            .trim_start_matches(['#', '@'])
            .trim();
        if let Some(reference) = comment
            .strip_prefix("sourceMappingURL")
            .and_then(|s| s.trim_start().strip_prefix('='))
        {
            found = Some(reference.trim().to_string());
        }
    }
    found
}

pub fn conventional_map(location: &str) -> Option<String> {
    let mut url = Url::parse(location).ok()?;
    if !matches!(url.scheme(), "http" | "https" | "file") || url.fragment().is_some() {
        return None;
    }
    let path = format!("{}.map", url.path());
    url.set_path(&path);
    Some(url.to_string())
}

pub fn decode_data(reference: &str, max: usize) -> Result<Vec<u8>> {
    let (header, payload) = reference
        .split_once(',')
        .ok_or_else(|| Error::Invalid("invalid data URL".into()))?;
    if payload.len() > max.saturating_mul(3) {
        return Err(Error::Invalid("data URL exceeds size limit".into()));
    }
    let bytes = if header.ends_with(";base64") {
        base64::engine::general_purpose::STANDARD
            .decode(payload)
            .map_err(|e| Error::Invalid(e.to_string()))?
    } else {
        let mut decoded = Vec::new();
        let mut i = 0;
        let raw = payload.as_bytes();
        while i < raw.len() {
            if raw[i] == b'%' && i + 2 < raw.len() {
                let h = std::str::from_utf8(&raw[i + 1..i + 3])
                    .map_err(|e| Error::Invalid(e.to_string()))?;
                decoded.push(u8::from_str_radix(h, 16).map_err(|e| Error::Invalid(e.to_string()))?);
                i += 3;
            } else {
                decoded.push(raw[i]);
                i += 1;
            }
        }
        decoded
    };
    if bytes.len() > max {
        return Err(Error::Invalid("data URL exceeds size limit".into()));
    }
    Ok(bytes)
}

pub fn source_location(map_url: &str, root: &str, source: &str) -> Option<String> {
    if let Ok(url) = Url::parse(source) {
        return matches!(url.scheme(), "http" | "https" | "file").then(|| url.to_string());
    }
    if root.contains("://")
        && !root.starts_with("http://")
        && !root.starts_with("https://")
        && !root.starts_with("file://")
    {
        return None;
    }
    let base = if root.is_empty() {
        map_url.to_string()
    } else {
        resolve(map_url, &format!("{}/", root.trim_end_matches('/')))?
    };
    resolve(&base, source)
}

pub fn module_location(
    base: &str,
    specifier: &str,
    imports: &BTreeMap<String, String>,
) -> Option<String> {
    if let Some(url) = imports.get(specifier) {
        return Some(url.clone());
    }
    if let Some((prefix, target)) = imports
        .iter()
        .filter(|(k, _)| k.ends_with('/') && specifier.starts_with(k.as_str()))
        .max_by_key(|(k, _)| k.len())
    {
        return resolve(target, &specifier[prefix.len()..]);
    }
    if specifier.starts_with('.') || specifier.starts_with('/') || Url::parse(specifier).is_ok() {
        resolve(base, specifier)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn maps_keep_query_and_ignore_strings() {
        assert_eq!(
            conventional_map("https://a.test/app.js?v=3").unwrap(),
            "https://a.test/app.js.map?v=3"
        );
        let a = Artifact::new(
            "x.js".into(),
            ArtifactKind::Script,
            b"const x='//# sourceMappingURL=fake';\n//# sourceMappingURL=real.map".to_vec(),
            "test".into(),
        );
        assert_eq!(map_reference(&a).as_deref(), Some("real.map"));
    }
    #[test]
    fn html_base_and_importmap() {
        let a = Artifact::new("https://app.test/".into(),ArtifactKind::Html,br#"<base href="/assets/"><script type="importmap">{"imports":{"lib":"./lib.js"}}</script><script src="app.js"></script><script type="module">import 'lib'</script>"#.to_vec(),"test".into());
        let h = html(&a);
        assert_eq!(h.scripts, ["https://app.test/assets/app.js"]);
        assert_eq!(h.imports["lib"], "https://app.test/assets/lib.js");
        assert_eq!(h.inline.len(), 1);
    }
    #[test]
    fn percent_inline_map_and_virtual_roots() {
        assert_eq!(
            decode_data("data:application/json,%7B%7D", 100).unwrap(),
            b"{}"
        );
        assert!(
            source_location("https://app.test/app.js.map", "webpack://app/", "src/x.ts").is_none()
        );
        assert_eq!(
            source_location("https://app.test/assets/app.js.map", "../src", "a.ts").unwrap(),
            "https://app.test/src/a.ts"
        );
    }
}

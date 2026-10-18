use crate::*;
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Component, Path, PathBuf},
};

/// A new output directory is required. All children are created by us and written with create_new.
/// Refusing pre-existing roots also prevents following attacker-controlled links during export.
pub struct Output {
    root: PathBuf,
}
impl Output {
    pub fn create(root: &Path) -> Result<Self> {
        if root.exists() || root.symlink_metadata().is_ok() {
            return Err(Error::Invalid(format!(
                "output already exists: {} (choose a new --out)",
                root.display()
            )));
        }
        if let Some(parent) = root.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)?;
        }
        fs::create_dir(root)?;
        let root = fs::canonicalize(root)?;
        for name in ["raw", "sources", "formatted"] {
            fs::create_dir(root.join(name))?;
        }
        Ok(Self { root })
    }
    pub fn write(&self, relative: &str, bytes: &[u8]) -> Result<()> {
        let path = Path::new(relative);
        if path
            .components()
            .any(|c| !matches!(c, Component::Normal(_)))
        {
            return Err(Error::Invalid("unsafe export path".into()));
        }
        let full = self.root.join(path);
        let parent = full
            .parent()
            .ok_or_else(|| Error::Invalid("missing export parent".into()))?;
        let mut current = self.root.clone();
        for part in path.parent().unwrap_or(Path::new("")).components() {
            current.push(part);
            match fs::symlink_metadata(&current) {
                Ok(meta) if meta.file_type().is_symlink() || !meta.is_dir() => {
                    return Err(Error::Invalid(
                        "export parent is not a regular directory".into(),
                    ));
                }
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => fs::create_dir(&current)?,
                Err(e) => return Err(e.into()),
            }
        }
        if !fs::canonicalize(parent)?.starts_with(&self.root) {
            return Err(Error::Invalid("export escaped output directory".into()));
        }
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(full)?
            .write_all(bytes)?;
        Ok(())
    }
    pub fn contains(&self, relative: &str) -> bool {
        self.root.join(relative).is_file()
    }
    pub fn finish(&self, report: &ScanReport) -> Result<()> {
        self.write("report.json", &serde_json::to_vec_pretty(report)?)?;
        let manifest = serde_json::json!({"schema_version":1,"artifacts":report.artifacts,"edges":report.edges,"recovered_sources":report.recovered_sources,"coverage":report.coverage});
        self.write("manifest.json", &serde_json::to_vec_pretty(&manifest)?)?;
        let mut md = format!(
            "# r3kj4\n\nTarget: `{}`\n\nStatus: {}\n\nArtifacts: {} · Sources: {} · Endpoints: {} · Findings: {}\n\n",
            report.options.target,
            if report.coverage.partial {
                "partial"
            } else {
                "complete"
            },
            report.artifacts.len(),
            report.recovered_sources.len(),
            report.endpoints.len(),
            report.findings.len()
        );
        md.push_str("## Endpoints\n\n");
        for e in &report.endpoints {
            md.push_str(&format!(
                "- `{}` `{}` — {}, {}\n",
                e.method,
                e.url,
                e.client,
                if e.observed { "observed" } else { "inferred" }
            ));
        }
        md.push_str("\n## Findings\n\n");
        for f in &report.findings {
            // JSON quoting prevents multiline secret values from breaking report structure.
            md.push_str(&format!(
                "- **{}** ({}, {}): {}\n",
                f.rule,
                f.confidence,
                f.severity,
                serde_json::to_string(&f.value)?
            ));
            for e in &f.evidence {
                md.push_str(&format!(
                    "  - {}:{}:{} [{}]\n",
                    e.location, e.line, e.column, e.method
                ));
            }
        }
        md.push_str("\n## Coverage and diagnostics\n\n");
        for page in &report.coverage.visited_pages {
            md.push_str(&format!("- Visited: {page}\n"));
        }
        for d in &report.diagnostics {
            md.push_str(&format!("- {}: {} — {}\n", d.code, d.location, d.message));
        }
        self.write("report.md", md.as_bytes())
    }
}

pub fn safe_source_path(logical: &str) -> String {
    logical
        .replace('\\', "/")
        .split('/')
        .filter(|s| !s.is_empty() && *s != "." && *s != "..")
        .map(|s| {
            let mut safe: String = s
                .chars()
                .map(|c| {
                    if c.is_ascii_alphanumeric() || "._-".contains(c) {
                        c
                    } else {
                        '_'
                    }
                })
                .take(100)
                .collect();
            safe = safe.trim_end_matches(['.', ' ']).to_string();
            let stem = safe.split('.').next().unwrap_or("").to_uppercase();
            if safe.is_empty()
                || [
                    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6",
                    "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7",
                    "LPT8", "LPT9",
                ]
                .contains(&stem.as_str())
            {
                safe.insert(0, '_');
            }
            safe
        })
        .collect::<Vec<_>>()
        .join("/")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn export_is_contained_and_never_overwrites() {
        let dir = tempfile::tempdir().unwrap();
        let out = Output::create(&dir.path().join("out")).unwrap();
        assert!(out.write("../escape", b"bad").is_err());
        out.write("sources/x.ts", b"ok").unwrap();
        assert!(out.write("sources/x.ts", b"new").is_err());
        assert_eq!(
            std::fs::read(dir.path().join("out/sources/x.ts")).unwrap(),
            b"ok"
        );
        assert!(Output::create(&dir.path().join("out")).is_err());
    }
    #[test]
    fn windows_names_and_traversal() {
        let p = safe_source_path("webpack://app/../../C:\\src\\CON.ts");
        assert!(!p.contains(":"));
        assert!(!p.contains(".."));
        assert!(p.ends_with("_CON.ts"));
    }
}

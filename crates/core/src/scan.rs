use crate::{
    analysis, discovery,
    output::{Output, safe_source_path},
    *,
};
use futures::{StreamExt, stream};
use rayon::prelude::*;
use reqwest::cookie::CookieStore;
use serde_json::Value;
use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::io::AsyncReadExt;
use tokio_util::sync::CancellationToken;
use url::Url;

#[derive(Clone)]
struct Job {
    location: String,
    kind: Option<ArtifactKind>,
    parent: String,
    relation: String,
    depth: usize,
}

struct Pipeline {
    report: ScanReport,
    output: Output,
    queue: VecDeque<Job>,
    seen: HashSet<String>,
    ids: HashSet<String>,
    local_root: Option<PathBuf>,
    imports: BTreeMap<String, String>,
    locations: HashMap<String, String>,
    source_refs: HashMap<String, Vec<usize>>,
    source_exports: HashSet<String>,
    analyzed: HashMap<String, analysis::Analysis>,
    preanalyzed: HashMap<String, analysis::Analysis>,
    execution_bases: HashMap<String, String>,
    pages: usize,
}

pub fn validate_options(options: &ScanOptions) -> Result<()> {
    if options.target.is_empty() {
        return Err(Error::Invalid("target is required".into()));
    }
    if options.concurrency == 0
        || options.jobs == 0
        || options.timeout_secs == 0
        || options.max_artifacts == 0
        || options.max_pages == 0
        || options.max_asset_bytes == 0
        || options.max_body_bytes == 0
        || options.max_total_bytes == 0
    {
        return Err(Error::Invalid(
            "timeouts, concurrency and size/count limits must be positive".into(),
        ));
    }
    for analyzer in &options.only {
        if !["secrets", "endpoints", "urls", "comments"].contains(&analyzer.as_str()) {
            return Err(Error::Invalid(format!("unknown analyzer: {analyzer}")));
        }
    }
    if let Some(base) = &options.base_url {
        let parsed = Url::parse(base).map_err(|e| Error::Invalid(format!("base URL: {e}")))?;
        if !matches!(parsed.scheme(), "http" | "https") {
            return Err(Error::Invalid("base URL must use HTTP(S)".into()));
        }
    }
    for (name, value) in &options.headers {
        reqwest::header::HeaderName::from_bytes(name.as_bytes())
            .map_err(|e| Error::Invalid(e.to_string()))?;
        reqwest::header::HeaderValue::from_str(value).map_err(|e| Error::Invalid(e.to_string()))?;
    }
    Ok(())
}

pub fn http_client(options: &ScanOptions) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(options.timeout_secs))
        .danger_accept_invalid_certs(options.insecure)
        .user_agent(concat!("r3kj4/", env!("CARGO_PKG_VERSION")));
    if let Some(proxy) = &options.proxy {
        builder = builder.proxy(reqwest::Proxy::all(proxy)?);
    }
    if let Some(cert) = &options.ca_cert {
        builder =
            builder.add_root_certificate(reqwest::Certificate::from_pem(&std::fs::read(cert)?)?);
    }
    Ok(builder.build()?)
}

pub async fn scan(
    options: ScanOptions,
    capture: RuntimeCapture,
    cancel: CancellationToken,
) -> Result<ScanReport> {
    validate_options(&options)?;
    let target_url = Url::parse(&options.target)
        .ok()
        .filter(|u| matches!(u.scheme(), "http" | "https"));
    if target_url.is_some() && options.offline {
        return Err(Error::Invalid(
            "an HTTP(S) target cannot be used with --offline".into(),
        ));
    }
    let local = if target_url.is_none() {
        Some(std::fs::canonicalize(&options.target)?)
    } else {
        None
    };
    let local_root = local.as_ref().map(|p| {
        if p.is_dir() {
            p.clone()
        } else {
            p.parent().unwrap_or(p).to_path_buf()
        }
    });
    let output = Output::create(&options.out)?;
    let mut pipeline = Pipeline {
        report: ScanReport::new(options.clone()),
        output,
        queue: VecDeque::new(),
        seen: HashSet::new(),
        ids: HashSet::new(),
        local_root,
        imports: BTreeMap::new(),
        locations: HashMap::new(),
        source_refs: HashMap::new(),
        source_exports: HashSet::new(),
        analyzed: HashMap::new(),
        preanalyzed: HashMap::new(),
        execution_bases: HashMap::new(),
        pages: 0,
    };
    pipeline.report.coverage = capture.coverage;
    pipeline.report.requests = capture.requests;
    pipeline.report.diagnostics = capture.diagnostics;
    pipeline.report.coverage.partial |= pipeline.report.diagnostics.iter().any(|d| d.partial);
    pipeline.report.coverage.total_bytes = 0;
    let jar = Arc::new(reqwest::cookie::Jar::default());
    let client = http_client(&options)?;
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(options.jobs)
        .build()
        .map_err(|e| Error::Invalid(e.to_string()))?;
    pipeline.prepare(&capture.artifacts.iter().collect::<Vec<_>>(), &pool);
    for artifact in capture.artifacts {
        pipeline.ingest(artifact, 0, &pool)?;
    }
    if let Some(url) = target_url {
        pipeline.enqueue(Job {
            location: url.to_string(),
            kind: None,
            parent: "input".into(),
            relation: "input".into(),
            depth: 0,
        });
    }
    if let Some(path) = local {
        let paths: Vec<PathBuf> = if path.is_dir() {
            let output_root = std::fs::canonicalize(&options.out)?;
            let mut found = vec![];
            for entry in walkdir::WalkDir::new(&path)
                .follow_links(false)
                .into_iter()
                .filter_entry(|e| !e.path().starts_with(&output_root))
            {
                match entry {
                    Ok(e) if e.file_type().is_file() => {
                        let extension = e
                            .path()
                            .extension()
                            .and_then(|s| s.to_str())
                            .unwrap_or("")
                            .to_lowercase();
                        if [
                            "js", "mjs", "cjs", "jsx", "ts", "mts", "cts", "tsx", "map", "maps",
                            "html", "htm",
                        ]
                        .contains(&extension.as_str())
                        {
                            found.push(e.into_path());
                        }
                    }
                    Err(e) => pipeline.report.diagnostic(
                        "local_walk",
                        &options.target,
                        e.to_string(),
                        true,
                    ),
                    _ => {}
                }
            }
            found.sort();
            found
        } else {
            vec![path]
        };
        for p in paths {
            if let Ok(url) = Url::from_file_path(&p) {
                pipeline.enqueue(Job {
                    location: url.to_string(),
                    kind: None,
                    parent: "input".into(),
                    relation: "input".into(),
                    depth: 0,
                });
            }
        }
    }
    loop {
        if cancel.is_cancelled() {
            pipeline.report.coverage.cancelled = true;
            pipeline.report.diagnostic(
                "cancelled",
                "scan",
                "scan cancelled; completed work preserved",
                true,
            );
            break;
        }
        if pipeline.queue.is_empty() {
            break;
        }
        let mut jobs = vec![];
        while jobs.len() < options.concurrency {
            let Some(job) = pipeline.queue.pop_front() else {
                break;
            };
            if let Some(id) = pipeline.locations.get(&job.location) {
                pipeline.report.edges.push(DiscoveryEdge {
                    from: job.parent,
                    to: id.clone(),
                    relation: job.relation,
                });
            } else {
                jobs.push(job);
            }
        }
        let root = pipeline.local_root.clone();
        let results = stream::iter(jobs.into_iter().map(|job| {
            let client = client.clone(); let jar = jar.clone(); let cancel = cancel.clone(); let root = root.clone(); let options = &options;
            async move {
                let result = tokio::select! { _ = cancel.cancelled() => Err(Error::Invalid("cancelled".into())), r = acquire(&job,&client,&jar,options,root.as_deref()) => r };
                (job,result)
            }
        })).buffer_unordered(options.concurrency).collect::<Vec<_>>().await;
        pipeline.prepare(
            &results
                .iter()
                .filter_map(|(_, result)| result.as_ref().ok()?.as_ref())
                .collect::<Vec<_>>(),
            &pool,
        );
        for (job, result) in results {
            match result {
                Ok(Some(artifact)) => {
                    pipeline.report.edges.push(DiscoveryEdge {
                        from: job.parent,
                        to: artifact.id.clone(),
                        relation: job.relation,
                    });
                    pipeline.locations.insert(job.location, artifact.id.clone());
                    pipeline.ingest(artifact, job.depth, &pool)?;
                }
                Ok(None) => pipeline.report.diagnostic(
                    "unavailable",
                    &job.location,
                    "resource not available",
                    false,
                ),
                Err(e) => {
                    pipeline
                        .report
                        .diagnostic("acquisition", &job.location, e.to_string(), true)
                }
            }
        }
        if pipeline.report.coverage.total_bytes >= options.max_total_bytes {
            if !pipeline.queue.is_empty() {
                pipeline.report.diagnostic(
                    "total_limit",
                    "scan",
                    "total acquisition limit reached with pending references",
                    true,
                );
            }
            break;
        }
    }
    if pipeline.report.artifacts.is_empty() && !pipeline.report.coverage.partial {
        pipeline.report.diagnostic(
            "no_artifacts",
            &options.target,
            "no input artifacts could be acquired",
            true,
        );
    }
    pipeline.resolve_sources()?;
    pipeline.finish_analysis();
    pipeline.correlate();
    pipeline.report.artifacts.sort_by(|a, b| a.id.cmp(&b.id));
    pipeline
        .report
        .endpoints
        .sort_by(|a, b| (&a.url, &a.method).cmp(&(&b.url, &b.method)));
    pipeline.report.findings.sort_by(|a, b| a.id.cmp(&b.id));
    pipeline.output.finish(&pipeline.report)?;
    Ok(pipeline.report)
}

impl Pipeline {
    fn prepare(&mut self, artifacts: &[&Artifact], pool: &rayon::ThreadPool) {
        let mut options = self.report.options.clone();
        if options.skip_analysis {
            options.only.clear();
        }
        let computed: HashMap<_, _> = pool.install(|| {
            artifacts
                .par_iter()
                .filter(|a| {
                    a.kind != ArtifactKind::SourceMap
                        && a.size <= options.max_asset_bytes
                        && !self.ids.contains(&a.id)
                        && !self.preanalyzed.contains_key(&a.id)
                })
                .map(|a| (a.id.clone(), analysis::analyze(a, &options)))
                .collect()
        });
        self.preanalyzed.extend(computed);
    }
    fn enqueue(&mut self, mut job: Job) {
        if self.report.options.analyze_only && job.relation != "input" {
            return;
        }
        if let Ok(mut url) = Url::parse(&job.location)
            && matches!(url.scheme(), "http" | "https")
        {
            url.set_fragment(None);
            job.location = url.to_string();
        }
        if self.report.options.offline
            && !job.location.starts_with("file:")
            && !job.location.starts_with("data:")
        {
            self.report.diagnostic(
                "offline_reference",
                &job.location,
                "remote reference left unresolved by --offline",
                false,
            );
            return;
        }
        if let Some(id) = self.locations.get(&job.location) {
            self.report.edges.push(DiscoveryEdge {
                from: job.parent,
                to: id.clone(),
                relation: job.relation,
            });
            return;
        }
        if self.seen.len() >= self.report.options.max_artifacts {
            self.report.diagnostic(
                "artifact_limit",
                &job.location,
                "artifact discovery limit reached",
                true,
            );
            return;
        }
        if self.seen.insert(job.location.clone()) {
            self.queue.push_back(job);
        }
    }
    fn ingest(&mut self, artifact: Artifact, depth: usize, pool: &rayon::ThreadPool) -> Result<()> {
        let mut pending = vec![artifact];
        while let Some(mut artifact) = pending.pop() {
            if artifact.execution_base.is_none() {
                artifact.execution_base = self.execution_bases.get(&artifact.location).cloned();
            }
            if !self.ids.insert(artifact.id.clone()) {
                continue;
            }
            if self.report.artifacts.len() >= self.report.options.max_artifacts
                || artifact.size > self.report.options.max_asset_bytes
                || artifact.size
                    > self
                        .report
                        .options
                        .max_total_bytes
                        .saturating_sub(self.report.coverage.total_bytes)
            {
                self.report.diagnostic(
                    "content_limit",
                    &artifact.location,
                    "content or artifact count limit reached",
                    true,
                );
                continue;
            }
            self.report.coverage.total_bytes += artifact.size;
            let raw_path = format!("raw/{}", artifact.hash);
            if !self.output.contains(&raw_path) {
                self.output.write(&raw_path, &artifact.content)?;
            }
            artifact.raw_path = Some(raw_path);
            self.locations
                .insert(artifact.location.clone(), artifact.id.clone());
            match artifact.kind {
                ArtifactKind::Html => {
                    let discovered = discovery::html(&artifact);
                    self.imports.extend(discovered.imports);
                    for mut child in discovered.inline {
                        child.execution_base = Some(discovered.base.clone());
                        self.report.edges.push(DiscoveryEdge {
                            from: artifact.id.clone(),
                            to: child.id.clone(),
                            relation: "inline_script".into(),
                        });
                        // Inline module specifiers resolve against the document's <base>.
                        self.imports
                            .insert(format!("@base:{}", child.id), discovered.base.clone());
                        pending.push(child);
                    }
                    for url in discovered.scripts {
                        self.execution_bases
                            .insert(url.clone(), discovered.base.clone());
                        self.enqueue(Job {
                            location: url,
                            kind: Some(ArtifactKind::Script),
                            parent: artifact.id.clone(),
                            relation: "script".into(),
                            depth,
                        });
                    }
                    if depth < self.report.options.max_depth {
                        for url in discovered.links {
                            if Url::parse(&url)
                                .ok()
                                .is_some_and(|u| self.report.options.navigation_allowed(&u))
                            {
                                if self.pages >= self.report.options.max_pages {
                                    self.report.diagnostic(
                                        "page_limit",
                                        &url,
                                        "page discovery limit reached",
                                        true,
                                    );
                                    break;
                                }
                                self.pages += 1;
                                self.enqueue(Job {
                                    location: url,
                                    kind: Some(ArtifactKind::Html),
                                    parent: artifact.id.clone(),
                                    relation: "link".into(),
                                    depth: depth + 1,
                                });
                            }
                        }
                    }
                }
                ArtifactKind::Script => {
                    if let Some(reference) = discovery::map_reference(&artifact) {
                        if reference.starts_with("data:") {
                            match discovery::decode_data(
                                &reference,
                                self.report.options.max_asset_bytes,
                            ) {
                                Ok(bytes) => {
                                    let mut child = Artifact::new(
                                        format!("{}#inline.map", artifact.location),
                                        ArtifactKind::SourceMap,
                                        bytes,
                                        "inline_map".into(),
                                    );
                                    child.execution_base = artifact.execution_base.clone();
                                    self.report.edges.push(DiscoveryEdge {
                                        from: artifact.id.clone(),
                                        to: child.id.clone(),
                                        relation: "source_map".into(),
                                    });
                                    pending.push(child);
                                }
                                Err(e) => self.report.diagnostic(
                                    "inline_map",
                                    &artifact.location,
                                    e.to_string(),
                                    true,
                                ),
                            }
                        } else if let Some(url) = discovery::resolve(&artifact.location, &reference)
                        {
                            if let Some(base) = &artifact.execution_base {
                                self.execution_bases.insert(url.clone(), base.clone());
                            }
                            self.enqueue(Job {
                                location: url,
                                kind: Some(ArtifactKind::SourceMap),
                                parent: artifact.id.clone(),
                                relation: "source_map".into(),
                                depth,
                            });
                        } else {
                            self.report.diagnostic(
                                "unresolved_map",
                                &artifact.location,
                                reference,
                                false,
                            );
                        }
                    }
                    if !artifact.context.starts_with("recovered:")
                        && let Some(url) = discovery::conventional_map(&artifact.location)
                    {
                        if let Some(base) = &artifact.execution_base {
                            self.execution_bases.insert(url.clone(), base.clone());
                        }
                        self.enqueue(Job {
                            location: url,
                            kind: Some(ArtifactKind::SourceMap),
                            parent: artifact.id.clone(),
                            relation: "source_map_probe".into(),
                            depth,
                        });
                    }
                }
                ArtifactKind::SourceMap => {
                    self.expand_map(&artifact, &mut pending, depth)?;
                    self.prepare(&pending.iter().collect::<Vec<_>>(), pool);
                }
                _ => {}
            }
            if artifact.kind != ArtifactKind::SourceMap {
                let mut options = self.report.options.clone();
                if options.skip_analysis {
                    options.only.clear();
                }
                let analyzed = self
                    .preanalyzed
                    .remove(&artifact.id)
                    .unwrap_or_else(|| pool.install(|| analysis::analyze(&artifact, &options)));
                if let Some(formatted) = &analyzed.formatted {
                    let relative = format!(
                        "formatted/{}.{}",
                        &artifact.id[..16],
                        if artifact
                            .location
                            .split(['?', '#'])
                            .next()
                            .unwrap_or("")
                            .ends_with(".ts")
                        {
                            "ts"
                        } else {
                            "js"
                        }
                    );
                    self.output.write(&relative, formatted.as_bytes())?;
                    artifact.formatted_path = Some(relative);
                }
                let base = self
                    .imports
                    .get(&format!("@base:{}", artifact.id))
                    .cloned()
                    .unwrap_or_else(|| artifact.location.clone());
                for module in &analyzed.modules {
                    if let Some(url) =
                        discovery::module_location(&base, &module.specifier, &self.imports)
                    {
                        if let Some(base) = &artifact.execution_base {
                            self.execution_bases.insert(url.clone(), base.clone());
                        }
                        self.enqueue(Job {
                            location: url,
                            kind: Some(ArtifactKind::Script),
                            parent: artifact.id.clone(),
                            relation: module.kind.clone(),
                            depth,
                        });
                    }
                }
                self.analyzed.insert(artifact.id.clone(), analyzed);
            }
            self.report.artifacts.push(artifact);
        }
        Ok(())
    }
    fn expand_map(
        &mut self,
        artifact: &Artifact,
        pending: &mut Vec<Artifact>,
        depth: usize,
    ) -> Result<()> {
        let data: Value = match serde_json::from_slice(&artifact.content) {
            Ok(data) => data,
            Err(e) => {
                self.report
                    .diagnostic("invalid_map", &artifact.location, e.to_string(), true);
                return Ok(());
            }
        };
        if let Err(e) = sourcemap::decode_slice(&artifact.content) {
            self.report
                .diagnostic("invalid_map", &artifact.location, e.to_string(), true);
            return Ok(());
        }
        if let Some(sections) = data.get("sections").and_then(Value::as_array) {
            for (index, section) in sections.iter().enumerate() {
                if let Some(map) = section.get("map") {
                    let mut child = Artifact::new(
                        format!("{}#section-{index}.map", artifact.location),
                        ArtifactKind::SourceMap,
                        serde_json::to_vec(map)?,
                        "map_section".into(),
                    );
                    child.execution_base = artifact.execution_base.clone();
                    self.report.edges.push(DiscoveryEdge {
                        from: artifact.id.clone(),
                        to: child.id.clone(),
                        relation: "map_section".into(),
                    });
                    pending.push(child);
                } else if let Some(url) = section
                    .get("url")
                    .and_then(Value::as_str)
                    .and_then(|u| discovery::resolve(&artifact.location, u))
                {
                    self.enqueue(Job {
                        location: url,
                        kind: Some(ArtifactKind::SourceMap),
                        parent: artifact.id.clone(),
                        relation: "map_section".into(),
                        depth,
                    });
                }
            }
            return Ok(());
        }
        let root = data.get("sourceRoot").and_then(Value::as_str).unwrap_or("");
        let contents = data.get("sourcesContent").and_then(Value::as_array);
        if let Some(sources) = data.get("sources").and_then(Value::as_array) {
            for (index, source) in sources.iter().enumerate() {
                let Some(logical) = source.as_str() else {
                    continue;
                };
                let logical = if root.is_empty() {
                    logical.to_string()
                } else {
                    format!("{}/{}", root.trim_end_matches('/'), logical)
                };
                let mut record = RecoveredSource {
                    map_id: artifact.id.clone(),
                    logical_path: logical.clone(),
                    artifact_id: None,
                    exported_path: None,
                    status: "unavailable".into(),
                    source_index: index,
                };
                if let Some(content) = contents.and_then(|a| a.get(index)).and_then(Value::as_str) {
                    let location = discovery::source_location(
                        &artifact.location,
                        root,
                        source.as_str().unwrap(),
                    )
                    .unwrap_or(logical.clone());
                    let kind = discovery::classify(&logical, content.as_bytes(), "");
                    let mut child = Artifact::new(
                        location,
                        kind,
                        content.as_bytes().to_vec(),
                        format!("recovered:{}:{index}", artifact.id),
                    );
                    child.execution_base = artifact.execution_base.clone();
                    record.artifact_id = Some(child.id.clone());
                    record.status = "embedded".into();
                    self.report.edges.push(DiscoveryEdge {
                        from: artifact.id.clone(),
                        to: child.id.clone(),
                        relation: "recovered_source".into(),
                    });
                    pending.push(child);
                } else if let Some(url) =
                    discovery::source_location(&artifact.location, root, source.as_str().unwrap())
                {
                    self.source_refs
                        .entry(url.clone())
                        .or_default()
                        .push(self.report.recovered_sources.len());
                    self.enqueue(Job {
                        location: url,
                        kind: None,
                        parent: artifact.id.clone(),
                        relation: "source_content".into(),
                        depth,
                    });
                } else {
                    self.report.diagnostic(
                        "source_unavailable",
                        &logical,
                        "source content is absent and its virtual path has no fetchable origin",
                        false,
                    );
                }
                self.report.recovered_sources.push(record);
            }
        }
        Ok(())
    }
    fn resolve_sources(&mut self) -> Result<()> {
        for (location, indices) in &self.source_refs {
            if let Some(id) = self.locations.get(location) {
                for i in indices {
                    self.report.recovered_sources[*i].artifact_id = Some(id.clone());
                    self.report.recovered_sources[*i].status = "external".into();
                }
            }
        }
        for record in &mut self.report.recovered_sources {
            let Some(artifact) = record
                .artifact_id
                .as_ref()
                .and_then(|id| self.report.artifacts.iter().find(|a| &a.id == id))
            else {
                record.status = "unavailable".into();
                record.artifact_id = None;
                continue;
            };
            let logical = safe_source_path(&record.logical_path);
            let logical = if logical.len() > 140 {
                format!(
                    "{}/{}",
                    &digest(logical.as_bytes())[..12],
                    logical.rsplit('/').next().unwrap_or("source")
                )
            } else {
                logical
            };
            let mut relative = format!("sources/{}/{logical}", &record.map_id[..12]);
            if logical.is_empty() {
                relative.push_str("source");
            }
            // Include index when case-insensitive filesystems or normalization make names collide.
            if !self.source_exports.insert(relative.to_lowercase()) {
                relative = format!(
                    "sources/{}/{}_{}",
                    &record.map_id[..12],
                    record.source_index,
                    logical.replace('/', "_")
                );
            }
            self.output.write(&relative, &artifact.content)?;
            record.exported_path = Some(relative);
        }
        Ok(())
    }
    fn finish_analysis(&mut self) {
        let maps: HashMap<_, _> = self
            .report
            .artifacts
            .iter()
            .filter(|a| a.kind == ArtifactKind::SourceMap)
            .filter_map(|a| {
                sourcemap::decode_slice(&a.content)
                    .ok()
                    .map(|decoded| (a.id.clone(), decoded))
            })
            .collect();
        for (id, mut a) in self.analyzed.drain() {
            for finding in &mut a.findings {
                for e in &mut finding.evidence {
                    map_evidence(&self.report, &maps, &id, e);
                }
            }
            for endpoint in &mut a.endpoints {
                for e in &mut endpoint.evidence {
                    map_evidence(&self.report, &maps, &id, e);
                }
            }
            for comment in &mut a.comments {
                map_evidence(&self.report, &maps, &id, &mut comment.evidence);
            }
            self.report.findings.extend(a.findings);
            self.report.endpoints.extend(a.endpoints);
            self.report.comments.extend(a.comments);
            self.report.modules.extend(a.modules);
            for d in a.diagnostics {
                self.report.coverage.partial |= d.partial;
                self.report.diagnostics.push(d);
            }
        }
        let mut findings: BTreeMap<String, Finding> = BTreeMap::new();
        for f in self.report.findings.drain(..) {
            if let Some(previous) = findings.get_mut(&f.id) {
                for e in f.evidence {
                    if !previous.evidence.contains(&e) {
                        previous.evidence.push(e);
                    }
                }
            } else {
                findings.insert(f.id.clone(), f);
            }
        }
        self.report.findings = findings.into_values().collect();
        for finding in &mut self.report.findings {
            finding.evidence.sort_by(|a, b| {
                (&a.location, a.start, &a.method, &a.artifact_id).cmp(&(
                    &b.location,
                    b.start,
                    &b.method,
                    &b.artifact_id,
                ))
            });
        }
        self.report.comments.sort_by(|a, b| {
            (&a.evidence.location, a.evidence.start).cmp(&(&b.evidence.location, b.evidence.start))
        });
        self.report.modules.sort_by(|a, b| {
            (&a.artifact_id, &a.specifier, &a.kind).cmp(&(&b.artifact_id, &b.specifier, &b.kind))
        });
        let mut endpoints: BTreeMap<(String, String, String), Endpoint> = BTreeMap::new();
        for endpoint in self.report.endpoints.drain(..) {
            let key = (
                endpoint.method.clone(),
                endpoint.url.clone(),
                endpoint.client.clone(),
            );
            if let Some(previous) = endpoints.get_mut(&key) {
                previous.evidence.extend(endpoint.evidence);
                previous.query_params.extend(endpoint.query_params);
                previous.headers.extend(endpoint.headers);
                previous.body_params.extend(endpoint.body_params);
                if endpoint.confidence == "high" {
                    previous.confidence = endpoint.confidence;
                }
            } else {
                endpoints.insert(key, endpoint);
            }
        }
        self.report.endpoints = endpoints.into_values().collect();
        for endpoint in &mut self.report.endpoints {
            endpoint.evidence.sort_by(|a, b| {
                (&a.location, a.start, &a.method, &a.artifact_id).cmp(&(
                    &b.location,
                    b.start,
                    &b.method,
                    &b.artifact_id,
                ))
            });
            endpoint.evidence.dedup();
            for names in [
                &mut endpoint.query_params,
                &mut endpoint.headers,
                &mut endpoint.body_params,
            ] {
                names.sort();
                names.dedup();
            }
        }
    }
    fn correlate(&mut self) {
        if !self.report.options.enabled("endpoints") || self.report.options.skip_analysis {
            return;
        }
        let artifacts = &self.report.artifacts;
        for endpoint in &mut self.report.endpoints {
            for evidence in &endpoint.evidence {
                let base = artifacts
                    .iter()
                    .find(|a| a.id == evidence.artifact_id)
                    .map(|a| {
                        a.execution_base
                            .as_deref()
                            .unwrap_or(&self.report.options.target)
                    })
                    .unwrap_or("");
                let resolved = discovery::resolve(base, &endpoint.url);
                for req in &self.report.requests {
                    let same = resolved
                        .as_deref()
                        .is_some_and(|u| urls_match(u, &req.url, &endpoint.query_params))
                        || endpoint.url == req.url;
                    if same && endpoint.method == req.method {
                        endpoint.observed = true;
                        if !endpoint.request_ids.contains(&req.id) {
                            endpoint.request_ids.push(req.id.clone());
                        }
                    }
                }
            }
        }
        for req in &self.report.requests {
            if !["XHR", "Fetch"].contains(&req.resource_type.as_str()) {
                continue;
            }
            if self
                .report
                .endpoints
                .iter()
                .any(|e| e.request_ids.contains(&req.id))
            {
                continue;
            }
            self.report.endpoints.push(Endpoint {
                method: req.method.clone(),
                url: req.url.clone(),
                client: "runtime".into(),
                confidence: "high".into(),
                query_params: req.query_params.clone(),
                headers: req.headers.keys().cloned().collect(),
                body_params: req.body_params.clone(),
                observed: true,
                evidence: vec![],
                request_ids: vec![req.id.clone()],
            });
        }
    }
}

fn urls_match(expected: &str, observed: &str, params: &[String]) -> bool {
    let (Ok(expected), Ok(observed)) = (Url::parse(expected), Url::parse(observed)) else {
        return false;
    };
    expected.origin() == observed.origin()
        && expected.path() == observed.path()
        && expected
            .query_pairs()
            .all(|pair| observed.query_pairs().any(|other| pair == other))
        && params
            .iter()
            .all(|key| observed.query_pairs().any(|(k, _)| k == key.as_str()))
}

fn map_evidence(
    report: &ScanReport,
    maps: &HashMap<String, sourcemap::DecodedMap>,
    id: &str,
    e: &mut Evidence,
) {
    let mut edges: Vec<_> = report
        .edges
        .iter()
        .filter(|edge| edge.from == id && edge.relation.starts_with("source_map"))
        .collect();
    edges.sort_by_key(|edge| if edge.relation == "source_map" { 0 } else { 1 });
    for edge in edges {
        if let Some(decoded) = maps.get(&edge.to)
            && let Some(token) = decoded.lookup_token((e.line - 1) as u32, (e.column - 1) as u32)
            && let Some(source) = token.get_source()
        {
            e.mapped_locations.push(MappedLocation {
                source: source.into(),
                line: token.get_src_line() as usize + 1,
                column: token.get_src_col() as usize + 1,
            });
            return;
        }
    }
}

async fn acquire(
    job: &Job,
    client: &reqwest::Client,
    jar: &reqwest::cookie::Jar,
    options: &ScanOptions,
    local_root: Option<&Path>,
) -> Result<Option<Artifact>> {
    let mut url = Url::parse(&job.location).map_err(|e| Error::Invalid(e.to_string()))?;
    if url.scheme() == "file" {
        let path = url
            .to_file_path()
            .map_err(|_| Error::Invalid("invalid local file URL".into()))?;
        let canonical = match tokio::fs::canonicalize(&path).await {
            Ok(p) => p,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if !options.offline {
                    if let (Some(base), Some(root)) = (&options.base_url, local_root) {
                        let plain_root = Url::from_directory_path(root)
                            .ok()
                            .and_then(|u| u.to_file_path().ok())
                            .unwrap_or_else(|| root.to_path_buf());
                        if let Ok(relative) = path.strip_prefix(&plain_root) {
                            let relative = relative.to_string_lossy().replace('\\', "/");
                            if let Some(remote) = discovery::resolve(base, &relative) {
                                let query = url.query().map(str::to_string);
                                url = Url::parse(&remote)
                                    .map_err(|e| Error::Invalid(e.to_string()))?;
                                url.set_query(query.as_deref());
                            } else {
                                return Ok(None);
                            }
                        } else {
                            return Err(Error::Invalid(
                                "local reference escapes input directory".into(),
                            ));
                        }
                    } else {
                        return Ok(None);
                    }
                } else {
                    return Ok(None);
                }
                PathBuf::new()
            }
            Err(e) => return Err(e.into()),
        };
        if !canonical.as_os_str().is_empty() {
            if !local_root.is_some_and(|root| canonical.starts_with(root)) {
                return Err(Error::Invalid(
                    "local reference escapes input directory".into(),
                ));
            }
            let file = tokio::fs::File::open(&canonical).await?;
            let mut bytes = vec![];
            file.take(options.max_asset_bytes as u64 + 1)
                .read_to_end(&mut bytes)
                .await?;
            if bytes.len() > options.max_asset_bytes {
                return Err(Error::Invalid("asset exceeds size limit".into()));
            }
            let kind = job
                .kind
                .clone()
                .unwrap_or_else(|| discovery::classify(&job.location, &bytes, ""));
            return Ok(Some(Artifact::new(
                job.location.clone(),
                kind,
                bytes,
                "local".into(),
            )));
        }
    }
    if url.scheme() == "data" {
        let bytes = discovery::decode_data(&job.location, options.max_asset_bytes)?;
        return Ok(Some(Artifact::new(
            format!("data:{}", digest(&bytes)),
            job.kind.clone().unwrap_or(ArtifactKind::Script),
            bytes,
            "data_url".into(),
        )));
    }
    if options.offline {
        return Err(Error::Invalid("network prohibited by --offline".into()));
    }
    if !matches!(url.scheme(), "http" | "https") {
        return Err(Error::Invalid("unsupported acquisition scheme".into()));
    }
    for _ in 0..10 {
        let mut request = client.get(url.clone());
        if options.credentials_allowed(&url) {
            for (name, value) in &options.headers {
                request = request.header(name, value);
            }
            if let Some(cookie) = &options.cookies {
                request = request.header(reqwest::header::COOKIE, cookie);
            } else if let Some(cookie) = jar.cookies(&url) {
                request = request.header(reqwest::header::COOKIE, cookie);
            }
        }
        let response = request.send().await?;
        if options.credentials_allowed(&url) {
            jar.set_cookies(
                &mut response
                    .headers()
                    .get_all(reqwest::header::SET_COOKIE)
                    .iter(),
                &url,
            );
        }
        if response.status().is_redirection() {
            let location = response
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| Error::Invalid("redirect without Location".into()))?;
            url = url
                .join(location)
                .map_err(|e| Error::Invalid(e.to_string()))?;
            if !matches!(url.scheme(), "http" | "https") {
                return Err(Error::Invalid("redirect uses unsupported scheme".into()));
            }
            if job.kind == Some(ArtifactKind::Html) && !options.navigation_allowed(&url) {
                return Err(Error::Invalid(
                    "navigation redirect leaves allowed origins".into(),
                ));
            }
            continue;
        }
        if response.status() == 404 || response.status() == 410 {
            return Ok(None);
        }
        let response = response.error_for_status()?;
        let headers: BTreeMap<_, _> = response
            .headers()
            .iter()
            .filter_map(|(k, v)| v.to_str().ok().map(|v| (k.to_string(), v.to_string())))
            .collect();
        if response
            .content_length()
            .is_some_and(|n| n > options.max_asset_bytes as u64)
        {
            return Err(Error::Invalid("asset exceeds size limit".into()));
        }
        let mut bytes = vec![];
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            if chunk.len() > options.max_asset_bytes.saturating_sub(bytes.len()) {
                return Err(Error::Invalid("asset exceeds size limit".into()));
            }
            bytes.extend_from_slice(&chunk);
        }
        let detected = discovery::classify(
            url.as_str(),
            &bytes,
            headers.get("content-type").map_or("", String::as_str),
        );
        // An HTML error page must not be parsed as a guessed source map or script.
        if detected == ArtifactKind::Html
            && matches!(
                job.kind,
                Some(ArtifactKind::SourceMap | ArtifactKind::Script)
            )
        {
            return Ok(None);
        }
        let kind = job.kind.clone().unwrap_or(detected);
        let mut artifact = Artifact::new(url.to_string(), kind, bytes, "http".into());
        artifact.headers = headers;
        return Ok(Some(artifact));
    }
    Err(Error::Invalid("redirect limit exceeded".into()))
}

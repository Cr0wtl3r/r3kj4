use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, path::PathBuf};

pub fn digest(bytes: impl AsRef<[u8]>) -> String {
    format!("{:x}", Sha256::digest(bytes.as_ref()))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ScanOptions {
    pub target: String,
    pub out: PathBuf,
    pub base_url: Option<String>,
    pub offline: bool,
    pub skip_analysis: bool,
    pub only: Vec<String>,
    pub timeout_secs: u64,
    pub concurrency: usize,
    pub jobs: usize,
    pub max_depth: usize,
    pub max_pages: usize,
    pub max_artifacts: usize,
    pub max_asset_bytes: usize,
    pub max_body_bytes: usize,
    pub max_total_bytes: usize,
    pub headers: BTreeMap<String, String>,
    pub cookies: Option<String>,
    pub credential_origins: Vec<String>,
    pub allow_origins: Vec<String>,
    pub proxy: Option<String>,
    pub ca_cert: Option<PathBuf>,
    pub insecure: bool,
    pub analyze_only: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            target: String::new(),
            out: "r3kj4-output".into(),
            base_url: None,
            offline: false,
            skip_analysis: false,
            only: vec![
                "secrets".into(),
                "endpoints".into(),
                "urls".into(),
                "comments".into(),
            ],
            timeout_secs: 20,
            concurrency: 8,
            jobs: std::thread::available_parallelism().map_or(1, |n| n.get().min(4)),
            max_depth: 2,
            max_pages: 25,
            max_artifacts: 10000,
            max_asset_bytes: 50 * 1024 * 1024,
            max_body_bytes: 2 * 1024 * 1024,
            max_total_bytes: 1024 * 1024 * 1024,
            headers: BTreeMap::new(),
            cookies: None,
            credential_origins: vec![],
            allow_origins: vec![],
            proxy: None,
            ca_cert: None,
            insecure: false,
            analyze_only: false,
        }
    }
}

impl ScanOptions {
    pub fn enabled(&self, name: &str) -> bool {
        self.only.iter().any(|x| x == name)
    }
    pub fn credentials_allowed(&self, url: &url::Url) -> bool {
        std::iter::once(&self.target)
            .chain(self.base_url.iter())
            .chain(self.credential_origins.iter())
            .filter_map(|s| url::Url::parse(s).ok())
            .any(|base| base.origin() == url.origin())
    }
    pub fn navigation_allowed(&self, url: &url::Url) -> bool {
        matches!(url.scheme(), "http" | "https")
            && std::iter::once(&self.target)
                .chain(self.allow_origins.iter())
                .filter_map(|s| url::Url::parse(s).ok())
                .any(|base| base.origin() == url.origin())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    Html,
    Script,
    SourceMap,
    Json,
    Text,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Artifact {
    pub id: String,
    pub hash: String,
    pub location: String,
    pub kind: ArtifactKind,
    pub context: String,
    pub execution_base: Option<String>,
    pub size: usize,
    pub raw_path: Option<String>,
    pub formatted_path: Option<String>,
    pub headers: BTreeMap<String, String>,
    #[serde(skip)]
    pub content: Vec<u8>,
}

impl Artifact {
    pub fn new(location: String, kind: ArtifactKind, content: Vec<u8>, context: String) -> Self {
        let hash = digest(&content);
        let id = digest(format!("{location}\0{context}\0{hash}"));
        Self {
            id,
            hash,
            location,
            kind,
            context,
            execution_base: None,
            size: content.len(),
            raw_path: None,
            formatted_path: None,
            headers: BTreeMap::new(),
            content,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryEdge {
    pub from: String,
    pub to: String,
    pub relation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveredSource {
    pub map_id: String,
    pub logical_path: String,
    pub artifact_id: Option<String>,
    pub exported_path: Option<String>,
    pub status: String,
    pub source_index: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Evidence {
    pub artifact_id: String,
    pub location: String,
    pub start: usize,
    pub end: usize,
    pub line: usize,
    pub column: usize,
    pub method: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mapped_locations: Vec<MappedLocation>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MappedLocation {
    pub source: String,
    pub line: usize,
    pub column: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Endpoint {
    pub method: String,
    pub url: String,
    pub client: String,
    pub confidence: String,
    pub query_params: Vec<String>,
    pub headers: Vec<String>,
    pub body_params: Vec<String>,
    pub observed: bool,
    pub evidence: Vec<Evidence>,
    pub request_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub rule: String,
    pub category: String,
    pub confidence: String,
    pub severity: String,
    pub value: String,
    pub evidence: Vec<Evidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Comment {
    pub text: String,
    pub tags: Vec<String>,
    pub evidence: Evidence,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleReference {
    pub artifact_id: String,
    pub specifier: String,
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeRequest {
    pub id: String,
    pub url: String,
    pub method: String,
    pub resource_type: String,
    pub headers: BTreeMap<String, String>,
    pub query_params: Vec<String>,
    pub body_params: Vec<String>,
    pub status: Option<u16>,
    pub initiator: serde_json::Value,
    pub body_artifact: Option<String>,
    pub failure: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Diagnostic {
    pub code: String,
    pub location: String,
    pub message: String,
    pub partial: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Coverage {
    pub runtime_requested: bool,
    pub visited_pages: Vec<String>,
    pub completed_steps: usize,
    pub captured_scripts: usize,
    pub total_bytes: usize,
    pub partial: bool,
    pub cancelled: bool,
}

#[derive(Debug, Default)]
pub struct RuntimeCapture {
    pub artifacts: Vec<Artifact>,
    pub requests: Vec<RuntimeRequest>,
    pub diagnostics: Vec<Diagnostic>,
    pub coverage: Coverage,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub schema_version: u32,
    pub tool_version: String,
    pub options: ScanOptions,
    pub artifacts: Vec<Artifact>,
    pub edges: Vec<DiscoveryEdge>,
    pub recovered_sources: Vec<RecoveredSource>,
    pub endpoints: Vec<Endpoint>,
    pub findings: Vec<Finding>,
    pub comments: Vec<Comment>,
    pub modules: Vec<ModuleReference>,
    pub requests: Vec<RuntimeRequest>,
    pub diagnostics: Vec<Diagnostic>,
    pub coverage: Coverage,
}

impl ScanReport {
    pub fn new(options: ScanOptions) -> Self {
        Self {
            schema_version: 1,
            tool_version: env!("CARGO_PKG_VERSION").into(),
            options,
            artifacts: vec![],
            edges: vec![],
            recovered_sources: vec![],
            endpoints: vec![],
            findings: vec![],
            comments: vec![],
            modules: vec![],
            requests: vec![],
            diagnostics: vec![],
            coverage: Coverage::default(),
        }
    }
    pub fn diagnostic(
        &mut self,
        code: &str,
        location: &str,
        message: impl Into<String>,
        partial: bool,
    ) {
        self.coverage.partial |= partial;
        self.diagnostics.push(Diagnostic {
            code: code.into(),
            location: location.into(),
            message: message.into(),
            partial,
        });
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SessionState {
    pub schema_version: u32,
    pub cookies: Vec<serde_json::Value>,
    pub origins: Vec<OriginState>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginState {
    pub origin: String,
    pub local_storage: BTreeMap<String, String>,
}

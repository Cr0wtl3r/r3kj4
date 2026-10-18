use crate::cdp::Cdp;
use anyhow::{Context, Result, bail, ensure};
use base64::Engine;
use r3kj4_core::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    path::PathBuf,
    process::Stdio,
    sync::{Arc, atomic::Ordering},
    time::{Duration, Instant},
};
use tokio::{
    process::{Child, Command},
    sync::Mutex,
};
use tokio_util::sync::CancellationToken;
use url::Url;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BrowserOptions {
    pub cdp_url: Option<String>,
    pub chrome: Option<PathBuf>,
    pub chrome_args: Vec<String>,
    pub flow: Option<Flow>,
    pub session: Option<PathBuf>,
    pub save_session: Option<PathBuf>,
    pub page_timeout_secs: u64,
    pub settle_ms: u64,
}
impl Default for BrowserOptions {
    fn default() -> Self {
        Self {
            cdp_url: None,
            chrome: None,
            chrome_args: vec![],
            flow: None,
            session: None,
            save_session: None,
            page_timeout_secs: 60,
            settle_ms: 1500,
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Flow {
    pub schema_version: u32,
    #[serde(default)]
    pub steps: Vec<FlowStep>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum FlowStep {
    Goto {
        url: String,
    },
    Fill {
        selector: String,
        value: Option<String>,
        env: Option<String>,
    },
    Click {
        selector: String,
    },
    Press {
        key: String,
        selector: Option<String>,
    },
    WaitFor {
        selector: Option<String>,
        url: Option<String>,
        #[serde(default = "default_wait")]
        timeout_ms: u64,
    },
    Wait {
        duration_ms: u64,
    },
}
fn default_wait() -> u64 {
    10000
}

pub fn chrome_executable(explicit: Option<&PathBuf>) -> Result<PathBuf> {
    if let Some(path) = explicit {
        ensure!(
            path.is_file(),
            "Chrome executable not found: {}",
            path.display()
        );
        return Ok(path.clone());
    }
    if let Some(path) = std::env::var_os("CHROME_PATH")
        && PathBuf::from(&path).is_file()
    {
        return Ok(path.into());
    }
    let candidates = if cfg!(target_os = "windows") {
        vec![
            "C:/Program Files/Google/Chrome/Application/chrome.exe",
            "C:/Program Files (x86)/Google/Chrome/Application/chrome.exe",
            "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe",
        ]
    } else if cfg!(target_os = "macos") {
        vec![
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "/Applications/Chromium.app/Contents/MacOS/Chromium",
        ]
    } else {
        vec![
            "/usr/bin/chromium",
            "/usr/bin/chromium-browser",
            "/usr/bin/google-chrome",
            "/opt/google/chrome/chrome",
        ]
    };
    for candidate in candidates {
        if PathBuf::from(candidate).is_file() {
            return Ok(candidate.into());
        }
    }
    if let Some(paths) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&paths) {
            for name in [
                "chromium",
                "chromium-browser",
                "google-chrome",
                "chrome.exe",
            ] {
                let path = dir.join(name);
                if path.is_file() {
                    return Ok(path);
                }
            }
        }
    }
    bail!("Chrome/Chromium not found; use --chrome, CHROME_PATH or --cdp-url")
}

struct BrowserProcess {
    child: Option<Child>,
    _profile: Option<tempfile::TempDir>,
}
impl BrowserProcess {
    async fn connect(options: &BrowserOptions, scan: &ScanOptions) -> Result<(Self, String)> {
        if let Some(endpoint) = &options.cdp_url {
            let websocket = if endpoint.starts_with("http://") || endpoint.starts_with("https://") {
                let client = reqwest::Client::builder()
                    .timeout(Duration::from_secs(scan.timeout_secs))
                    .build()?;
                let version: Value = client
                    .get(format!("{}/json/version", endpoint.trim_end_matches('/')))
                    .send()
                    .await?
                    .error_for_status()?
                    .json()
                    .await?;
                version["webSocketDebuggerUrl"].as_str().context("CDP endpoint did not return webSocketDebuggerUrl; supply the reachable ws:// URL")?.to_string()
            } else {
                endpoint.clone()
            };
            return Ok((
                Self {
                    child: None,
                    _profile: None,
                },
                websocket,
            ));
        }
        let executable = chrome_executable(options.chrome.as_ref())?;
        let profile = tempfile::tempdir()?;
        let mut command = Command::new(executable);
        command
            .args([
                "--headless=new",
                "--remote-debugging-address=127.0.0.1",
                "--remote-debugging-port=0",
                "--no-first-run",
                "--no-default-browser-check",
                "--disable-background-networking",
                "--disable-extensions",
            ])
            .arg(format!("--user-data-dir={}", profile.path().display()))
            .args(&options.chrome_args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        #[cfg(windows)]
        command.creation_flags(0x08000000);
        let mut child = command.spawn().context("launch Chrome")?;
        let start = Instant::now();
        loop {
            if let Ok(port) =
                tokio::fs::read_to_string(profile.path().join("DevToolsActivePort")).await
            {
                let mut lines = port.lines();
                if let (Some(port), Some(path)) = (lines.next(), lines.next()) {
                    return Ok((
                        Self {
                            child: Some(child),
                            _profile: Some(profile),
                        },
                        format!("ws://127.0.0.1:{port}{path}"),
                    ));
                }
            }
            if let Some(status) = child.try_wait()? {
                bail!(
                    "Chrome exited before CDP was ready ({status}); verify sandbox support and browser arguments"
                );
            }
            if start.elapsed() > Duration::from_secs(scan.timeout_secs) {
                child.kill().await?;
                bail!("Chrome CDP startup timed out");
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
    async fn close(&mut self) {
        if let Some(child) = &mut self.child {
            let _ = child.kill().await;
            let _ = child.wait().await;
        }
    }
}

pub async fn doctor(options: &BrowserOptions, scan: &ScanOptions) -> Result<Value> {
    let (mut process, endpoint) = BrowserProcess::connect(options, scan).await?;
    let connection = Cdp::connect(
        &endpoint,
        Duration::from_secs(scan.timeout_secs),
        scan.max_asset_bytes,
    )
    .await;
    let result = match connection {
        Ok((cdp, _)) => {
            let version = cdp.command(None, "Browser.getVersion", json!({})).await;
            cdp.shutdown();
            version
        }
        Err(e) => Err(e),
    };
    process.close().await;
    result
}

#[derive(Default)]
struct State {
    capture: RuntimeCapture,
    requests: HashMap<String, usize>,
    response_mime: HashMap<String, String>,
    sessions: HashSet<String>,
    scripts: HashSet<String>,
    context: String,
    root_target: String,
    storage: BTreeMap<String, BTreeMap<String, String>>,
    active_jobs: usize,
    execution_bases: HashMap<String, String>,
}
impl State {
    fn diagnostic(
        &mut self,
        code: &str,
        location: &str,
        message: impl Into<String>,
        partial: bool,
    ) {
        self.capture.coverage.partial |= partial;
        self.capture.diagnostics.push(Diagnostic {
            code: code.into(),
            location: location.into(),
            message: message.into(),
            partial,
        });
    }
    fn add(&mut self, artifact: Artifact, options: &ScanOptions) -> Option<String> {
        if self.capture.artifacts.iter().any(|a| a.id == artifact.id) {
            return Some(artifact.id);
        }
        if self.capture.artifacts.len() >= options.max_artifacts
            || artifact.size
                > options
                    .max_total_bytes
                    .saturating_sub(self.capture.coverage.total_bytes)
            || artifact.size > options.max_asset_bytes
        {
            self.diagnostic(
                "runtime_limit",
                &artifact.location,
                "runtime capture size/count limit reached",
                true,
            );
            return None;
        }
        self.capture.coverage.total_bytes += artifact.size;
        let id = artifact.id.clone();
        self.capture.artifacts.push(artifact);
        Some(id)
    }
}

pub async fn capture(
    scan: &ScanOptions,
    browser: &BrowserOptions,
    cancel: CancellationToken,
) -> RuntimeCapture {
    let state = Arc::new(Mutex::new(State::default()));
    state.lock().await.capture.coverage.runtime_requested = true;
    match capture_inner(scan, browser, cancel.clone(), state.clone()).await {
        Ok(()) => {}
        Err(e) => state
            .lock()
            .await
            .diagnostic("runtime", &scan.target, format!("{e:#}"), true),
    }
    if cancel.is_cancelled() {
        let mut s = state.lock().await;
        s.capture.coverage.cancelled = true;
        s.capture.coverage.partial = true;
    }
    std::mem::take(&mut state.lock().await.capture)
}

async fn capture_inner(
    scan: &ScanOptions,
    browser: &BrowserOptions,
    cancel: CancellationToken,
    state: Arc<Mutex<State>>,
) -> Result<()> {
    ensure!(!scan.offline, "--runtime cannot be used with --offline");
    let target = Url::parse(&scan.target)?;
    ensure!(
        matches!(target.scheme(), "http" | "https"),
        "runtime target must be HTTP(S)"
    );
    ensure!(
        browser.page_timeout_secs > 0,
        "page timeout must be positive"
    );
    if let Some(flow) = &browser.flow {
        ensure!(flow.schema_version == 1, "unsupported flow schema_version");
    }
    let (mut process, endpoint) = BrowserProcess::connect(browser, scan).await?;
    let connected = Cdp::connect(
        &endpoint,
        Duration::from_secs(scan.timeout_secs),
        scan.max_asset_bytes,
    )
    .await;
    let (cdp, mut events) = match connected {
        Ok(c) => c,
        Err(e) => {
            process.close().await;
            return Err(e);
        }
    };
    let mut context = String::new();
    let mut processor = None;
    let outcome: Result<()> = async {
        let mut params = json!({"disposeOnDetach":true});
        if let Some(proxy) = &scan.proxy {
            let mut proxy = Url::parse(proxy)?; let _ = proxy.set_username(""); let _ = proxy.set_password(None);
            params["proxyServer"] = proxy.to_string().into();
        }
        context = cdp.command(None,"Target.createBrowserContext",params).await?["browserContextId"].as_str().context("missing browserContextId")?.into();
        state.lock().await.context = context.clone();
        let target_id = cdp.command(None,"Target.createTarget",json!({"url":"about:blank","browserContextId":context})).await?["targetId"].as_str().context("missing targetId")?.to_string();
        state.lock().await.root_target = target_id.clone();
        let event_cdp = cdp.clone(); let event_scan = scan.clone(); let event_state = state.clone(); let event_cancel = cancel.clone();
        processor = Some(tokio::spawn(async move {
            let mut jobs = tokio::task::JoinSet::new();
            loop {
                let event = tokio::select! {
                    _ = event_cancel.cancelled() => break,
                    result = jobs.join_next(), if !jobs.is_empty() => {
                        if let Some(Err(e)) = result { event_state.lock().await.diagnostic("cdp_task","CDP",e.to_string(),true); }
                        continue;
                    },
                    event = events.recv() => {let Some(event) = event else {break;};event},
                };
                let location = event["method"].as_str().unwrap_or("event").to_string();
                if location == "Debugger.scriptParsed" || location == "Network.loadingFinished" || location == "Target.attachedToTarget" {
                    if jobs.len() >= 256 {event_state.lock().await.diagnostic("cdp_task_limit",&location,"runtime processing backlog exceeded",true);continue;}
                    let cdp = event_cdp.clone();let scan = event_scan.clone();let state = event_state.clone();
                    state.lock().await.active_jobs += 1;
                    jobs.spawn(async move {
                        if let Err(e) = handle_event(&cdp,&scan,&state,event).await {state.lock().await.diagnostic("cdp_event",&location,format!("{e:#}"),true);}
                        state.lock().await.active_jobs -= 1;
                    });
                } else if let Err(e) = handle_event(&event_cdp,&event_scan,&event_state,event).await { event_state.lock().await.diagnostic("cdp_event",&location,format!("{e:#}"),true); }
            }
        }));
        let session = cdp.command(None,"Target.attachToTarget",json!({"targetId":target_id,"flatten":true})).await?["sessionId"].as_str().context("missing sessionId")?.to_string();
        // Register related workers before navigation; every child session configures its own descendants.
        cdp.command(None,"Target.autoAttachRelated",json!({"targetId":target_id,"waitForDebuggerOnStart":true,"filter":[{"type":"service_worker"},{"exclude":true}]})).await?;
        let ready = Instant::now();
        while !state.lock().await.sessions.contains(&session) {
            ensure!(ready.elapsed() < Duration::from_secs(scan.timeout_secs),"root CDP session initialization timed out");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        restore_session(&cdp,&session,&context,scan,browser).await?;
        navigate(&cdp,&session,&scan.target,scan,browser,&cancel).await?;
        state.lock().await.capture.coverage.visited_pages.push(target.to_string());
        if let Some(flow) = &browser.flow {
            for step in &flow.steps {
                tokio::select! {
                    _ = cancel.cancelled() => bail!("cancelled"),
                    result = tokio::time::timeout(Duration::from_secs(browser.page_timeout_secs),run_step(&cdp,&session,step,scan,browser,&cancel)) => result.context("flow step exceeded page budget")??,
                }
                state.lock().await.capture.coverage.completed_steps += 1;
            }
        }
        let first = snapshot(&cdp,&session,scan,&state).await?;
        let mut queue: VecDeque<(String,usize)> = first.into_iter().map(|u| (u,1)).collect();
        let mut visited = HashSet::from([target.to_string()]);
        while let Some((url,depth)) = queue.pop_front() {
            if cancel.is_cancelled() { bail!("cancelled"); }
            if depth > scan.max_depth || !visited.insert(url.clone()) { continue; }
            let parsed = Url::parse(&url)?; if !scan.navigation_allowed(&parsed) { continue; }
            if state.lock().await.capture.coverage.visited_pages.len() >= scan.max_pages {
                state.lock().await.diagnostic("runtime_page_limit",&url,"navigation page limit reached",true); break;
            }
            if let Err(e) = navigate(&cdp,&session,&url,scan,browser,&cancel).await { state.lock().await.diagnostic("runtime_navigation",&url,format!("{e:#}"),true); continue; }
            state.lock().await.capture.coverage.visited_pages.push(url);
            match snapshot(&cdp,&session,scan,&state).await {
                Ok(links) => queue.extend(links.into_iter().take(scan.max_artifacts).map(|u| (u,depth+1))),
                Err(e) => state.lock().await.diagnostic("runtime_snapshot","page",e.to_string(),true),
            }
        }
        // Let already queued getResponseBody/getScriptSource commands drain before disposing the context.
        let drain = Instant::now();
        loop {
            let pending = cdp.command(Some(&session),"Runtime.evaluate",json!({"expression":"0\n//# sourceURL=r3kj4-internal://drain.js","returnByValue":true})).await;
            if pending.is_err() || drain.elapsed() > Duration::from_secs(scan.timeout_secs) { break; }
            tokio::time::sleep(Duration::from_millis(100)).await;
            if state.lock().await.active_jobs == 0 { break; }
        }
        if let Some(path) = &browser.save_session {
            let cookies = cdp.command(None,"Storage.getCookies",json!({"browserContextId":context})).await?["cookies"].as_array().cloned().unwrap_or_default();
            let origins = state.lock().await.storage.iter().map(|(origin,storage)| OriginState {origin:origin.clone(),local_storage:storage.clone()}).collect();
            let session = SessionState {schema_version:1,cookies,origins};
            let mut file = tokio::fs::OpenOptions::new().write(true).create_new(true).open(path).await.context("session output exists or is not writable")?;
            use tokio::io::AsyncWriteExt;
            file.write_all(&serde_json::to_vec_pretty(&session)?).await?;
        }
        Ok(())
    }.await;
    if !context.is_empty()
        && let Err(error) = cdp
            .command(
                None,
                "Target.disposeBrowserContext",
                json!({"browserContextId":context}),
            )
            .await
    {
        state.lock().await.diagnostic(
            "runtime_cleanup",
            "browser context",
            error.to_string(),
            true,
        );
    }
    if let Some(processor) = processor {
        processor.abort();
        let _ = processor.await;
    }
    let lost = cdp.lost_events.load(Ordering::Relaxed);
    if lost > 0 {
        state.lock().await.diagnostic(
            "cdp_event_overflow",
            "CDP",
            format!("{lost} events exceeded the queue; runtime coverage is partial"),
            true,
        );
    }
    if process.child.is_some() {
        let _ = cdp.command(None, "Browser.close", json!({})).await;
    }
    cdp.shutdown();
    process.close().await;
    outcome
}

async fn setup_session(cdp: &Cdp, session: &str, kind: &str, scan: &ScanOptions) -> Result<()> {
    // Service workers may be paused before their script has been fetched. Resume bootstrap so
    // Network.enable can complete; Debugger.enable subsequently enumerates already parsed scripts.
    if kind == "service_worker" {
        cdp.command(Some(session), "Runtime.runIfWaitingForDebugger", json!({}))
            .await?;
    }
    cdp.command(Some(session),"Network.enable",json!({"maxTotalBufferSize":scan.max_asset_bytes.saturating_mul(2),"maxResourceBufferSize":scan.max_asset_bytes})).await?;
    cdp.command(Some(session), "Runtime.enable", json!({}))
        .await?;
    cdp.command(
        Some(session),
        "Debugger.enable",
        json!({"maxScriptsCacheSize":scan.max_asset_bytes}),
    )
    .await?;
    if scan.insecure {
        cdp.command(
            Some(session),
            "Security.setIgnoreCertificateErrors",
            json!({"ignore":true}),
        )
        .await?;
    }
    if kind == "page" || kind == "iframe" {
        cdp.command(Some(session), "Page.enable", json!({})).await?;
        cdp.command(Some(session),"Fetch.enable",json!({"patterns":[{"urlPattern":"*","requestStage":"Request"}],"handleAuthRequests":true})).await?;
    }
    cdp.command(Some(session),"Target.setAutoAttach",json!({"autoAttach":true,"waitForDebuggerOnStart":true,"flatten":true,"filter":[{"type":"service_worker","exclude":true},{"exclude":false}]})).await?;
    cdp.command(Some(session), "Runtime.runIfWaitingForDebugger", json!({}))
        .await?;
    Ok(())
}

async fn handle_event(
    cdp: &Cdp,
    scan: &ScanOptions,
    state: &Arc<Mutex<State>>,
    event: Value,
) -> Result<()> {
    let method = event["method"].as_str().unwrap_or("");
    let params = &event["params"];
    let session = event["sessionId"].as_str().unwrap_or("");
    if std::env::var_os("R3KJ4_CDP_TRACE").is_some() {
        eprintln!("CDP event {session} {method}");
    }
    match method {
        "Target.attachedToTarget" => {
            let child = params["sessionId"]
                .as_str()
                .context("attached target without session")?;
            let kind = params["targetInfo"]["type"].as_str().unwrap_or("");
            if std::env::var_os("R3KJ4_CDP_TRACE").is_some() {
                eprintln!(
                    "ATTACH {kind} waiting={} sid={child}",
                    params["waitingForDebugger"]
                );
            }
            let context = params["targetInfo"]["browserContextId"].as_str();
            let own = state.lock().await.context.clone();
            if context.is_some_and(|c| c != own) {
                cdp.command(None, "Target.detachFromTarget", json!({"sessionId":child}))
                    .await?;
                return Ok(());
            }
            if state.lock().await.sessions.contains(child) {
                return Ok(());
            }
            let result = setup_session(cdp, child, kind, scan).await;
            if result.is_err() {
                let _ = cdp
                    .command(Some(child), "Runtime.runIfWaitingForDebugger", json!({}))
                    .await;
            }
            result?;
            state.lock().await.sessions.insert(child.into());
        }
        "Fetch.authRequired" => {
            let mut response = json!({"response":"CancelAuth"});
            if params["authChallenge"]["source"] == "Proxy"
                && let Some(proxy) = &scan.proxy
                && let Ok(proxy) = Url::parse(proxy)
            {
                response = json!({"response":"ProvideCredentials","username":proxy.username(),"password":proxy.password().unwrap_or("")});
            }
            cdp.command(
                Some(session),
                "Fetch.continueWithAuth",
                json!({"requestId":params["requestId"],"authChallengeResponse":response}),
            )
            .await?;
        }
        "Fetch.requestPaused" => {
            let url = params["request"]["url"].as_str().unwrap_or("");
            let parsed = Url::parse(url).ok();
            if params["resourceType"] == "Document"
                && parsed
                    .as_ref()
                    .is_some_and(|u| !scan.navigation_allowed(u) && u.scheme() != "about")
            {
                cdp.command(
                    Some(session),
                    "Fetch.failRequest",
                    json!({"requestId":params["requestId"],"errorReason":"BlockedByClient"}),
                )
                .await?;
                state.lock().await.diagnostic(
                    "runtime_scope",
                    url,
                    "document navigation blocked outside allowed origins",
                    false,
                );
            } else {
                let mut headers: BTreeMap<String, String> =
                    json_headers(&params["request"]["headers"]);
                for name in scan.headers.keys() {
                    headers.retain(|k, _| !k.eq_ignore_ascii_case(name));
                }
                if scan.cookies.is_some() {
                    headers.retain(|k, _| !k.eq_ignore_ascii_case("cookie"));
                }
                if parsed.as_ref().is_some_and(|u| scan.credentials_allowed(u)) {
                    headers.extend(scan.headers.clone());
                    if let Some(cookie) = &scan.cookies {
                        headers.insert("Cookie".into(), cookie.clone());
                    }
                }
                let headers: Vec<Value> = headers
                    .into_iter()
                    .map(|(name, value)| json!({"name":name,"value":value}))
                    .collect();
                cdp.command(
                    Some(session),
                    "Fetch.continueRequest",
                    json!({"requestId":params["requestId"],"headers":headers}),
                )
                .await?;
            }
        }
        "Network.requestWillBeSent" => {
            let id = format!("{session}:{}", params["requestId"].as_str().unwrap_or(""));
            let req = &params["request"];
            let url = req["url"].as_str().unwrap_or("");
            if !url.starts_with("http://") && !url.starts_with("https://") {
                return Ok(());
            }
            let query_params = Url::parse(url)
                .ok()
                .map(|u| u.query_pairs().map(|(k, _)| k.into_owned()).collect())
                .unwrap_or_default();
            let body_params = req["postData"].as_str().map(body_keys).unwrap_or_default();
            let mut s = state.lock().await;
            if s.capture.requests.len() >= scan.max_artifacts {
                s.diagnostic(
                    "runtime_request_limit",
                    url,
                    "request inventory limit reached",
                    true,
                );
                return Ok(());
            }
            let index = s.capture.requests.len();
            // Redirect hops retain distinct records while the CDP request ID follows the latest hop.
            let request = RuntimeRequest {
                id: format!("{id}:{index}"),
                url: url.into(),
                method: req["method"].as_str().unwrap_or("GET").into(),
                resource_type: params["type"].as_str().unwrap_or("").into(),
                headers: json_headers(&req["headers"]),
                query_params,
                body_params,
                status: None,
                initiator: params["initiator"].clone(),
                body_artifact: None,
                failure: None,
            };
            s.capture.requests.push(request);
            s.requests.insert(id, index);
        }
        "Network.requestWillBeSentExtraInfo" => {
            let id = format!("{session}:{}", params["requestId"].as_str().unwrap_or(""));
            let mut s = state.lock().await;
            if let Some(index) = s.requests.get(&id).copied() {
                s.capture.requests[index].headers = json_headers(&params["headers"]);
            }
        }
        "Network.responseReceived" => {
            let id = format!("{session}:{}", params["requestId"].as_str().unwrap_or(""));
            let mut s = state.lock().await;
            if let Some(index) = s.requests.get(&id).copied() {
                let resp = &params["response"];
                s.capture.requests[index].status = resp["status"].as_f64().map(|n| n as u16);
                s.response_mime.insert(
                    id.clone(),
                    resp["mimeType"].as_str().unwrap_or("").to_string(),
                );
                let headers = json!({"request_headers":s.capture.requests[index].headers,"response_headers":resp["headers"]});
                let a = Artifact::new(
                    format!("{}#headers-{}", s.capture.requests[index].url, index),
                    ArtifactKind::Json,
                    serde_json::to_vec(&headers)?,
                    "runtime_headers".into(),
                );
                s.add(a, scan);
            }
        }
        "Network.loadingFinished" => {
            let id = format!("{session}:{}", params["requestId"].as_str().unwrap_or(""));
            let info = {
                let s = state.lock().await;
                s.requests.get(&id).copied().map(|index| {
                    (
                        index,
                        s.capture.requests[index].url.clone(),
                        s.response_mime.get(&id).cloned().unwrap_or_default(),
                    )
                })
            };
            if let Some((index, url, mime)) = info {
                let code = mime.contains("javascript") || mime.contains("typescript");
                let text = code || mime.contains("json") || mime.starts_with("text/");
                if !text {
                    return Ok(());
                }
                let limit = if code {
                    scan.max_asset_bytes
                } else {
                    scan.max_body_bytes
                };
                if params["encodedDataLength"]
                    .as_f64()
                    .is_some_and(|size| size > limit as f64)
                {
                    state.lock().await.diagnostic(
                        "runtime_body_limit",
                        &url,
                        "response exceeds body limit",
                        true,
                    );
                    return Ok(());
                }
                match cdp
                    .command(
                        Some(session),
                        "Network.getResponseBody",
                        json!({"requestId":params["requestId"]}),
                    )
                    .await
                {
                    Ok(body) => {
                        let raw = body["body"].as_str().unwrap_or("");
                        let bytes = if body["base64Encoded"] == true {
                            base64::engine::general_purpose::STANDARD.decode(raw)?
                        } else {
                            raw.as_bytes().to_vec()
                        };
                        if bytes.len() > limit {
                            state.lock().await.diagnostic(
                                "runtime_body_limit",
                                &url,
                                "decoded response exceeds body limit",
                                true,
                            );
                            return Ok(());
                        }
                        let kind = discovery::classify(&url, &bytes, &mime);
                        let artifact =
                            Artifact::new(url, kind, bytes, format!("runtime_response:{id}"));
                        let mut s = state.lock().await;
                        let artifact_id = s.add(artifact, scan);
                        s.capture.requests[index].body_artifact = artifact_id;
                    }
                    Err(e) => state.lock().await.diagnostic(
                        "runtime_body_unavailable",
                        &url,
                        e.to_string(),
                        true,
                    ),
                }
            }
        }
        "Network.loadingFailed" => {
            let id = format!("{session}:{}", params["requestId"].as_str().unwrap_or(""));
            let mut s = state.lock().await;
            if let Some(index) = s.requests.get(&id).copied() {
                let error = params["errorText"].as_str().unwrap_or("request failed");
                s.capture.requests[index].failure = Some(error.into());
                let url = s.capture.requests[index].url.clone();
                s.diagnostic(
                    "runtime_request_failed",
                    &url,
                    error,
                    error != "net::ERR_BLOCKED_BY_CLIENT",
                );
            }
        }
        "Debugger.scriptParsed" => {
            let script_id = params["scriptId"].as_str().unwrap_or("");
            let key = format!("{session}:{script_id}");
            let url = params["url"].as_str().unwrap_or("");
            if url.starts_with("r3kj4-internal:") {
                return Ok(());
            }
            if !state.lock().await.scripts.insert(key.clone()) {
                return Ok(());
            }
            if params["length"]
                .as_u64()
                .is_some_and(|n| n > scan.max_asset_bytes as u64)
            {
                state.lock().await.diagnostic(
                    "runtime_script_limit",
                    url,
                    "script exceeds size limit",
                    true,
                );
                return Ok(());
            }
            let source = cdp
                .command(
                    Some(session),
                    "Debugger.getScriptSource",
                    json!({"scriptId":script_id}),
                )
                .await?;
            let location = if url.is_empty() {
                format!("runtime://{session}/{script_id}.js")
            } else {
                url.to_string()
            };
            let mut artifact = Artifact::new(
                location.clone(),
                ArtifactKind::Script,
                source["scriptSource"]
                    .as_str()
                    .unwrap_or("")
                    .as_bytes()
                    .to_vec(),
                format!("runtime_script:{key}"),
            );
            let execution_key = format!("{session}:{}", params["executionContextId"]);
            let cached = state
                .lock()
                .await
                .execution_bases
                .get(&execution_key)
                .cloned();
            let base = if let Some(base) = cached {
                base
            } else {
                let value=cdp.command(Some(session),"Runtime.evaluate",json!({"contextId":params["executionContextId"],"expression":internal("globalThis.document?.baseURI || globalThis.location?.href || ''".into()),"returnByValue":true})).await;
                let base = value
                    .ok()
                    .and_then(|v| v["result"]["value"].as_str().map(str::to_string))
                    .filter(|u| u.starts_with("http"))
                    .unwrap_or_else(|| scan.target.clone());
                state
                    .lock()
                    .await
                    .execution_bases
                    .insert(execution_key, base.clone());
                base
            };
            artifact.execution_base = Some(base);
            let map = params["sourceMapURL"].as_str().filter(|s| !s.is_empty());
            if let Some(map) = map {
                artifact.headers.insert("sourcemap".into(), map.into());
            }
            {
                let mut s = state.lock().await;
                s.capture.coverage.captured_scripts += 1;
                s.add(artifact, scan);
            }
            if let Some(map) = map.filter(|m| !m.starts_with("data:")) {
                let base = if location.starts_with("http") {
                    &location
                } else {
                    &scan.target
                };
                if let Some(url) = discovery::resolve(base, map).filter(|u| u.starts_with("http")) {
                    let script = format!(
                        "(async()=>{{const r=await fetch({},{{credentials:'include'}});if(!r.ok)return null;const reader=r.body.getReader();let n=0,chunks=[];for(;;){{const v=await reader.read();if(v.done)break;n+=v.value.length;if(n>{}){{await reader.cancel();return null}}chunks.push(v.value)}}const a=new Uint8Array(n);let p=0;for(const c of chunks){{a.set(c,p);p+=c.length}}return new TextDecoder().decode(a)}})()",
                        serde_json::to_string(&url)?,
                        scan.max_asset_bytes
                    );
                    if let Ok(Value::String(content)) =
                        cdp.evaluate(session, internal(script)).await
                    {
                        let map = Artifact::new(
                            url,
                            ArtifactKind::SourceMap,
                            content.into_bytes(),
                            "runtime_authenticated_map".into(),
                        );
                        state.lock().await.add(map, scan);
                    }
                }
            }
        }
        _ => {}
    }
    Ok(())
}

fn json_headers(value: &Value) -> BTreeMap<String, String> {
    value
        .as_object()
        .map(|o| {
            o.iter()
                .map(|(k, v)| {
                    (
                        k.clone(),
                        v.as_str()
                            .map(str::to_string)
                            .unwrap_or_else(|| v.to_string()),
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}
fn body_keys(text: &str) -> Vec<String> {
    if let Ok(Value::Object(map)) = serde_json::from_str::<Value>(text) {
        map.keys().cloned().collect()
    } else {
        url::form_urlencoded::parse(text.as_bytes())
            .map(|(k, _)| k.into_owned())
            .take(1000)
            .collect()
    }
}
fn internal(script: String) -> String {
    format!("{script}\n//# sourceURL=r3kj4-internal://evaluate.js")
}

async fn restore_session(
    cdp: &Cdp,
    session: &str,
    context: &str,
    scan: &ScanOptions,
    browser: &BrowserOptions,
) -> Result<()> {
    if let Some(path) = &browser.session {
        let state: SessionState = serde_json::from_slice(&tokio::fs::read(path).await?)?;
        ensure!(
            state.schema_version == 1,
            "unsupported session schema_version"
        );
        if !state.cookies.is_empty() {
            cdp.command(
                None,
                "Storage.setCookies",
                json!({"cookies":state.cookies,"browserContextId":context}),
            )
            .await?;
        }
        let script = internal(format!(
            "(()=>{{const states={};for(const s of states){{if(location.origin===s.origin){{for(const [k,v]of Object.entries(s.local_storage))localStorage.setItem(k,v)}}}}}})()",
            serde_json::to_string(&state.origins)?
        ));
        cdp.command(
            Some(session),
            "Page.addScriptToEvaluateOnNewDocument",
            json!({"source":script}),
        )
        .await?;
    }
    if let Some(cookies) = &scan.cookies {
        for pair in cookies.split(';') {
            if let Some((name, value)) = pair.trim().split_once('=') {
                cdp.command(
                    Some(session),
                    "Network.setCookie",
                    json!({"name":name,"value":value,"url":scan.target}),
                )
                .await?;
            }
        }
    }
    Ok(())
}

async fn navigate(
    cdp: &Cdp,
    session: &str,
    url: &str,
    scan: &ScanOptions,
    browser: &BrowserOptions,
    cancel: &CancellationToken,
) -> Result<()> {
    tokio::time::timeout(
        Duration::from_secs(browser.page_timeout_secs),
        navigate_inner(cdp, session, url, scan, browser, cancel),
    )
    .await
    .context("navigation exceeded page budget")?
}

async fn navigate_inner(
    cdp: &Cdp,
    session: &str,
    url: &str,
    scan: &ScanOptions,
    browser: &BrowserOptions,
    cancel: &CancellationToken,
) -> Result<()> {
    let parsed = Url::parse(url)?;
    ensure!(
        scan.navigation_allowed(&parsed),
        "navigation outside allowed origins: {url}"
    );
    let deadline = Instant::now();
    let response = tokio::select! {_=cancel.cancelled()=>bail!("cancelled"),r=cdp.command(Some(session),"Page.navigate",json!({"url":url}))=>r?};
    if let Some(error) = response["errorText"].as_str() {
        bail!("navigation: {error}");
    }
    loop {
        if cancel.is_cancelled() {
            bail!("cancelled");
        }
        if let Ok(value) = cdp
            .evaluate(session, internal("document.readyState".into()))
            .await
            && (value == "complete" || value == "interactive")
        {
            break;
        }
        ensure!(
            deadline.elapsed() < Duration::from_secs(browser.page_timeout_secs.min(30)),
            "navigation timed out"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    tokio::select! {_=cancel.cancelled()=>bail!("cancelled"),_=tokio::time::sleep(Duration::from_millis(browser.settle_ms.min(browser.page_timeout_secs*1000)))=>{}}
    Ok(())
}
async fn run_step(
    cdp: &Cdp,
    session: &str,
    step: &FlowStep,
    scan: &ScanOptions,
    browser: &BrowserOptions,
    cancel: &CancellationToken,
) -> Result<()> {
    match step {
        FlowStep::Goto { url } => navigate(cdp, session, url, scan, browser, cancel).await?,
        FlowStep::Fill {
            selector,
            value,
            env,
        } => {
            ensure!(
                value.is_some() ^ env.is_some(),
                "fill requires exactly one of value or env"
            );
            let value = match (value, env) {
                (Some(v), _) => v.clone(),
                (_, Some(e)) => std::env::var(e)
                    .with_context(|| format!("missing environment variable: {e}"))?,
                _ => unreachable!(),
            };
            cdp.evaluate(session,internal(format!("(()=>{{const e=document.querySelector({});if(!e)throw Error('fill selector missing');e.focus();const p=e instanceof HTMLTextAreaElement?HTMLTextAreaElement.prototype:HTMLInputElement.prototype;const s=Object.getOwnPropertyDescriptor(p,'value').set;s.call(e,{});e.dispatchEvent(new Event('input',{{bubbles:true}}));e.dispatchEvent(new Event('change',{{bubbles:true}}));}})()",serde_json::to_string(selector)?,serde_json::to_string(&value)?))).await?;
        }
        FlowStep::Click { selector } => {
            cdp.evaluate(session,internal(format!("(()=>{{const e=document.querySelector({});if(!e)throw Error('click selector missing');e.click()}})()",serde_json::to_string(selector)?))).await?;
        }
        FlowStep::Press { key, selector } => {
            if let Some(selector) = selector {
                cdp.evaluate(session,internal(format!("(()=>{{const e=document.querySelector({});if(!e)throw Error('press selector missing');e.focus()}})()",serde_json::to_string(selector)?))).await?;
            }
            let code = match key.as_str() {
                "Enter" => 13,
                "Tab" => 9,
                "Escape" => 27,
                "Backspace" => 8,
                "ArrowDown" => 40,
                "ArrowUp" => 38,
                _ => 0,
            };
            cdp.command(Some(session),"Input.dispatchKeyEvent",json!({"type":"keyDown","key":key,"windowsVirtualKeyCode":code,"text":if key=="Enter" {"\r"} else {""}})).await?;
            cdp.command(
                Some(session),
                "Input.dispatchKeyEvent",
                json!({"type":"keyUp","key":key,"windowsVirtualKeyCode":code}),
            )
            .await?;
        }
        FlowStep::WaitFor {
            selector,
            url,
            timeout_ms,
        } => {
            ensure!(
                selector.is_some() ^ url.is_some(),
                "wait_for requires exactly one of selector or url"
            );
            let expression = if let Some(selector) = selector {
                format!(
                    "!!document.querySelector({})",
                    serde_json::to_string(selector)?
                )
            } else {
                format!(
                    "location.href === {}",
                    serde_json::to_string(url.as_ref().unwrap())?
                )
            };
            let start = Instant::now();
            loop {
                if cancel.is_cancelled() {
                    bail!("cancelled");
                }
                if cdp
                    .evaluate(session, internal(expression.clone()))
                    .await
                    .unwrap_or(Value::Bool(false))
                    == true
                {
                    break;
                }
                ensure!(
                    start.elapsed() < Duration::from_millis(*timeout_ms),
                    "wait_for timed out"
                );
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
        FlowStep::Wait { duration_ms } => {
            ensure!(
                *duration_ms <= browser.page_timeout_secs * 1000,
                "wait exceeds page budget"
            );
            tokio::select! {_=cancel.cancelled()=>bail!("cancelled"),_=tokio::time::sleep(Duration::from_millis(*duration_ms))=>{}}
        }
    }
    Ok(())
}

async fn snapshot(
    cdp: &Cdp,
    session: &str,
    scan: &ScanOptions,
    state: &Arc<Mutex<State>>,
) -> Result<Vec<String>> {
    let value=cdp.evaluate(session,internal(format!("(()=>{{const html=document.documentElement?.outerHTML||'';return {{url:location.href,origin:location.origin,html:html.slice(0,{}),truncated:html.length>{},links:Array.from(document.querySelectorAll('a[href]')).slice(0,{}).map(a=>a.href),storage:Object.fromEntries(Object.entries(localStorage))}}}})()",scan.max_asset_bytes,scan.max_asset_bytes,scan.max_artifacts))).await?;
    let url = value["url"].as_str().unwrap_or(&scan.target);
    let mut s = state.lock().await;
    if value["truncated"] == true {
        s.diagnostic("runtime_dom_limit", url, "DOM snapshot truncated", true);
    }
    s.add(
        Artifact::new(
            url.into(),
            ArtifactKind::Html,
            value["html"].as_str().unwrap_or("").as_bytes().to_vec(),
            "runtime_dom".into(),
        ),
        scan,
    );
    if let Some(origin) = value["origin"].as_str() {
        s.storage
            .insert(origin.into(), json_headers(&value["storage"]));
    }
    if !s.capture.coverage.visited_pages.iter().any(|p| p == url) {
        s.capture.coverage.visited_pages.push(url.into());
    }
    Ok(value["links"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default())
}

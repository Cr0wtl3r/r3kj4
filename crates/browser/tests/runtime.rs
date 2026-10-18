use r3kj4_browser::{BrowserOptions, Flow, FlowStep, capture};
use r3kj4_core::*;
use std::{collections::BTreeMap, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::Mutex,
};
use tokio_util::sync::CancellationToken;

struct Fixture {
    url: String,
    requests: Arc<Mutex<Vec<String>>>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}
async fn fixture() -> Fixture {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let requests = Arc::new(Mutex::new(vec![]));
    let recorded = requests.clone();
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            let recorded = recorded.clone();
            tokio::spawn(async move {
                let mut bytes = vec![0u8; 16384];
                let Ok(n) = socket.read(&mut bytes).await else {
                    return;
                };
                let request = String::from_utf8_lossy(&bytes[..n]).to_string();
                recorded.lock().await.push(request.clone());
                let path = request
                    .lines()
                    .next()
                    .unwrap_or("")
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or("/")
                    .split('?')
                    .next()
                    .unwrap_or("/");
                let (status,mime,body,extra)=match path {
            "/"=>(200,"text/html",r#"<!DOCTYPE html><html><body><script src='/main.js'></script><iframe src='/frame'></iframe><a href='/next'>next</a><input id='user'><input id='pass'><button id='login' onclick="fetch('/auth',{method:'POST'}).then(()=>{localStorage.setItem('logged','yes');document.body.dataset.logged='yes';return import('/protected.js')})">login</button></body></html>"#.to_string(),""),
            "/main.js"=>(200,"application/javascript",r#"globalThis.mainMarker='main-source-marker';fetch('/api/data?from=runtime');const x=new XMLHttpRequest();x.open('GET','/api/xhr');x.send();import('/lazy.js');eval("globalThis.evalMarker='eval-source-marker';//# sourceURL=runtime-eval.js");new Worker('/worker.js');new Worker(URL.createObjectURL(new Blob(["globalThis.blobMarker='blob-worker-source-marker';fetch('/api/blob')"],{type:'application/javascript'})));navigator.serviceWorker.register('/sw.js');//# sourceMappingURL=/main.js.map"#.to_string(),""),
            "/main.js.map"=>(200,"application/json",serde_json::json!({"version":3,"sources":["src/main.ts"],"sourcesContent":["// original-source-marker\nconst client_secret='originalSecret9AbcD1234567';"],"names":[],"mappings":"AAAA"}).to_string(),""),
            "/lazy.js"=>(200,"application/javascript","globalThis.lazyMarker='lazy-source-marker';".into(),""),
            "/worker.js"=>(200,"application/javascript","globalThis.workerMarker='worker-source-marker';fetch('/api/worker');".into(),""),
            "/sw.js"=>(200,"application/javascript","globalThis.swMarker='service-worker-source-marker';self.addEventListener('install',()=>self.skipWaiting());".into(),"Service-Worker-Allowed: /\r\n"),
            "/frame"=>(200,"text/html","<script>globalThis.frameMarker='frame-source-marker';fetch('/api/frame')</script>".into(),""),
            "/next"=>(200,"text/html","<script>globalThis.nextMarker='next-page-source-marker'</script>".into(),""),
            "/restore"=>(200,"text/html","<!doctype html><html><body><script>document.body.dataset.restored=localStorage.getItem('restored');fetch('/api/restored')</script><script src='/protected.js'></script></body></html>".into(),""),
            "/auth"=>(200,"application/json","{}".into(),"Set-Cookie: auth=fixture; Path=/; HttpOnly\r\n"),
            "/protected.js"=>(200,"application/javascript","globalThis.protectedMarker='protected-source-marker';//# sourceMappingURL=/protected.js.map".into(),""),
            "/protected.js.map" if request.to_lowercase().contains("auth=fixture")=>(200,"application/json",serde_json::json!({"version":3,"sources":["src/private.ts"],"sourcesContent":["// authenticated-original-marker"],"names":[],"mappings":"AAAA"}).to_string(),""),
            "/protected.js.map"=>(401,"application/json","{}".into(),""),
            p if p.starts_with("/api/")=>(200,"application/json",r#"{"client_secret":"runtimeJsonSecret9AbcD1234567"}"#.into(),""),
            _=>(404,"text/plain","missing".into(),""),
        };
                let response = format!(
                    "HTTP/1.1 {status} OK\r\nContent-Type: {mime}\r\nContent-Length: {}\r\nConnection: close\r\n{extra}\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
            });
        }
    });
    Fixture {
        url,
        requests,
        task,
    }
}

// These tests exercise a real browser. Run with --ignored; CI installs Chromium or uses Chrome.
#[tokio::test]
#[ignore = "requires Chrome/Chromium"]
async fn captures_all_contexts_and_authenticated_sources() {
    let server = fixture().await;
    let temp = tempfile::tempdir().unwrap();
    let scan_options = ScanOptions {
        target: server.url.clone(),
        out: temp.path().join("out"),
        max_depth: 1,
        max_pages: 3,
        ..Default::default()
    };
    let browser = BrowserOptions {
        settle_ms: 1000,
        flow: Some(Flow {
            schema_version: 1,
            steps: vec![
                FlowStep::Fill {
                    selector: "#user".into(),
                    value: Some("fixture".into()),
                    env: None,
                },
                FlowStep::Click {
                    selector: "#login".into(),
                },
                FlowStep::WaitFor {
                    selector: Some("body[data-logged='yes']".into()),
                    url: None,
                    timeout_ms: 5000,
                },
                FlowStep::Wait { duration_ms: 500 },
            ],
        }),
        save_session: Some(temp.path().join("state.session.json")),
        ..Default::default()
    };
    let capture = capture(&scan_options, &browser, CancellationToken::new()).await;
    assert!(!capture.coverage.partial, "{:?}", capture.diagnostics);
    for (url, marker) in [
        ("/main.js", "main-source-marker"),
        ("/lazy.js", "lazy-source-marker"),
        ("runtime-eval.js", "eval-source-marker"),
        ("blob:", "blob-worker-source-marker"),
        ("/worker.js", "worker-source-marker"),
        ("/frame", "frame-source-marker"),
        ("/sw.js", "service-worker-source-marker"),
        ("/next", "next-page-source-marker"),
        ("/protected.js", "protected-source-marker"),
    ] {
        assert!(
            capture
                .artifacts
                .iter()
                .any(|a| a.context.starts_with("runtime_script:")
                    && a.location.contains(url)
                    && String::from_utf8_lossy(&a.content).contains(marker)),
            "missing script {url}: {marker}; diagnostics={:?}; sources={:?}",
            capture.diagnostics,
            capture
                .artifacts
                .iter()
                .map(|a| (&a.location, &a.context))
                .collect::<Vec<_>>()
        );
    }
    assert_eq!(capture.coverage.completed_steps, 4);
    assert!(
        capture
            .requests
            .iter()
            .any(|r| r.url.ends_with("/api/xhr") && r.resource_type == "XHR")
    );
    assert!(
        capture
            .artifacts
            .iter()
            .any(|a| a.context == "runtime_authenticated_map"
                && String::from_utf8_lossy(&a.content).contains("authenticated-original-marker"))
    );
    let session: SessionState =
        serde_json::from_slice(&std::fs::read(temp.path().join("state.session.json")).unwrap())
            .unwrap();
    assert!(session.cookies.iter().any(|c| c["name"] == "auth"));
    assert!(
        session
            .origins
            .iter()
            .any(|o| o.local_storage.get("logged") == Some(&"yes".into()))
    );
    let report = r3kj4_core::scan(scan_options, capture, CancellationToken::new())
        .await
        .unwrap();
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.value == "runtimeJsonSecret9AbcD1234567")
    );
    assert!(
        report
            .recovered_sources
            .iter()
            .any(|s| s.logical_path == "src/private.ts" && s.exported_path.is_some())
    );
    assert!(
        server
            .requests
            .lock()
            .await
            .iter()
            .any(|r| r.starts_with("POST /auth"))
    );
}

#[tokio::test]
#[ignore = "requires Chrome/Chromium; 20-run adapter acceptance gate"]
async fn repeated_capture_gate() {
    let server = fixture().await;
    let options = ScanOptions {
        target: server.url.clone(),
        max_depth: 0,
        ..Default::default()
    };
    let browser = BrowserOptions {
        settle_ms: 700,
        ..Default::default()
    };
    for iteration in 0..20 {
        let c = tokio::time::timeout(
            Duration::from_secs(30),
            capture(&options, &browser, CancellationToken::new()),
        )
        .await
        .expect("capture hung");
        assert!(
            !c.coverage.partial,
            "iteration {iteration}: {:?}",
            c.diagnostics
        );
        for (url, marker) in [
            ("/main.js", "main-source-marker"),
            ("/lazy.js", "lazy-source-marker"),
            ("runtime-eval.js", "eval-source-marker"),
            ("blob:", "blob-worker-source-marker"),
            ("/worker.js", "worker-source-marker"),
            ("/sw.js", "service-worker-source-marker"),
        ] {
            assert!(
                c.artifacts
                    .iter()
                    .any(|a| a.context.starts_with("runtime_script:")
                        && a.location.contains(url)
                        && String::from_utf8_lossy(&a.content).contains(marker)),
                "iteration {iteration}, missing {url}: {marker}: {:?}",
                c.diagnostics
            );
        }
        assert!(
            c.requests
                .iter()
                .any(|r| r.url.contains("/api/data?from=runtime"))
        );
    }
}

#[tokio::test]
#[ignore = "requires Chrome/Chromium"]
async fn session_restore_and_remote_cdp() {
    let server = fixture().await;
    let temp = tempfile::tempdir().unwrap();
    let state = SessionState {
        schema_version: 1,
        cookies: vec![serde_json::json!({"name":"auth","value":"fixture","url":server.url})],
        origins: vec![OriginState {
            origin: server.url.clone(),
            local_storage: BTreeMap::from([("restored".into(), "yes".into())]),
        }],
    };
    let session = temp.path().join("restore.session.json");
    std::fs::write(&session, serde_json::to_vec(&state).unwrap()).unwrap();
    let options = ScanOptions {
        target: format!("{}/restore", server.url),
        max_depth: 0,
        ..Default::default()
    };
    // Start an independent browser, connect through HTTP discovery, and verify it survives capture.
    let profile = tempfile::tempdir().unwrap();
    let mut command = tokio::process::Command::new(r3kj4_browser::chrome_executable(None).unwrap());
    command
        .args([
            "--headless=new",
            "--remote-debugging-port=0",
            "--no-first-run",
        ])
        .arg(format!("--user-data-dir={}", profile.path().display()))
        .arg("about:blank")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true);
    #[cfg(windows)]
    command.creation_flags(0x08000000);
    let mut child = command.spawn().unwrap();
    let port = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Ok(p) =
                tokio::fs::read_to_string(profile.path().join("DevToolsActivePort")).await
            {
                break p;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
    let endpoint = format!("http://127.0.0.1:{}", port.lines().next().unwrap());
    let c = capture(
        &options,
        &BrowserOptions {
            session: Some(session.clone()),
            cdp_url: Some(endpoint.clone()),
            settle_ms: 500,
            ..Default::default()
        },
        CancellationToken::new(),
    )
    .await;
    assert!(!c.coverage.partial, "{:?}", c.diagnostics);
    assert!(c.artifacts.iter().any(|a| a.context == "runtime_dom"
        && String::from_utf8_lossy(&a.content).contains("data-restored=\"yes\"")));
    assert!(
        c.artifacts
            .iter()
            .any(|a| a.context == "runtime_authenticated_map"
                && String::from_utf8_lossy(&a.content).contains("authenticated-original-marker"))
    );
    assert!(
        child.try_wait().unwrap().is_none(),
        "capture closed the remote browser"
    );
    let ws = format!(
        "ws://127.0.0.1:{}{}",
        port.lines().next().unwrap(),
        port.lines().nth(1).unwrap()
    );
    let second = capture(
        &options,
        &BrowserOptions {
            session: Some(session),
            cdp_url: Some(ws),
            settle_ms: 500,
            ..Default::default()
        },
        CancellationToken::new(),
    )
    .await;
    assert!(!second.coverage.partial, "{:?}", second.diagnostics);
    let tabs: serde_json::Value = reqwest::get(format!("{endpoint}/json/list"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        tabs.as_array()
            .unwrap()
            .iter()
            .filter(|t| t["type"] == "page")
            .count(),
        1,
        "isolated capture context was not disposed: {tabs}"
    );
    assert!(!tabs.as_array().unwrap().iter().any(|t| {
        t["url"]
            .as_str()
            .is_some_and(|u| u.starts_with(&server.url))
    }));
    child.kill().await.unwrap();
    child.wait().await.unwrap();
}

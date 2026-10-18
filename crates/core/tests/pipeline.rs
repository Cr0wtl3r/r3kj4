use r3kj4_core::*;
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use tokio_util::sync::CancellationToken;

struct Server {
    url: String,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}
async fn server(
    handler: impl Fn(&str) -> (u16, String, String, String) + Send + Sync + 'static,
) -> Server {
    let socket = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", socket.local_addr().unwrap());
    let handler = Arc::new(handler);
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut connection, _)) = socket.accept().await else {
                break;
            };
            let handler = handler.clone();
            tokio::spawn(async move {
                let mut buffer = vec![0; 16384];
                let Ok(n) = connection.read(&mut buffer).await else {
                    return;
                };
                let raw = String::from_utf8_lossy(&buffer[..n]);
                let (status, mime, body, headers) = handler(&raw);
                let response = format!(
                    "HTTP/1.1 {status} OK\r\nContent-Type: {mime}\r\nContent-Length: {}\r\nConnection: close\r\n{headers}\r\n{body}",
                    body.len()
                );
                let _ = connection.write_all(response.as_bytes()).await;
            });
        }
    });
    Server { url, task }
}
fn map(sources: serde_json::Value, contents: serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({"version":3,"sources":sources,"sourcesContent":contents,"names":[],"mappings":"AAAA"})).unwrap()
}
fn options(target: String, out: std::path::PathBuf) -> ScanOptions {
    ScanOptions {
        target,
        out,
        ..Default::default()
    }
}

#[tokio::test]
async fn offline_map_only_exact_empty_unicode_and_conflicting_paths() {
    let temp = tempfile::tempdir().unwrap();
    let input = temp.path().join("maps");
    std::fs::create_dir(&input).unwrap();
    let contents = serde_json::json!([
        "const emoji='🔥';\n// exact\r\n",
        "",
        "const x=1;",
        "const y=2;"
    ]);
    std::fs::write(
        input.join("app.maps"),
        map(
            serde_json::json!([
                "webpack://app/src/emoji.ts",
                "src/empty.ts",
                "../../src/A.ts",
                "../../src/a.ts"
            ]),
            contents.clone(),
        ),
    )
    .unwrap();
    let mut opt = options(input.to_string_lossy().into(), temp.path().join("out"));
    opt.offline = true;
    let report = scan(
        opt.clone(),
        RuntimeCapture::default(),
        CancellationToken::new(),
    )
    .await
    .unwrap();
    assert_eq!(report.recovered_sources.len(), 4);
    for (i, source) in report.recovered_sources.iter().enumerate() {
        assert_eq!(
            std::fs::read(opt.out.join(source.exported_path.as_ref().unwrap())).unwrap(),
            contents[i].as_str().unwrap().as_bytes()
        );
        assert_eq!(source.status, "embedded");
    }
    assert!(!temp.path().join("src").exists());
    let serialized = serde_json::to_value(&report).unwrap();
    assert_eq!(serialized["schema_version"], 1);
    assert!(serialized["artifacts"][0].get("content").is_none());
}

#[tokio::test]
async fn indexed_and_inline_maps_preserve_originals() {
    let temp = tempfile::tempdir().unwrap();
    let input = temp.path().join("input");
    std::fs::create_dir(&input).unwrap();
    let section: serde_json::Value = serde_json::from_slice(&map(
        serde_json::json!(["a.ts"]),
        serde_json::json!(["const api='/api';"]),
    ))
    .unwrap();
    std::fs::write(input.join("index.map"),serde_json::to_vec(&serde_json::json!({"version":3,"sections":[{"offset":{"line":0,"column":0},"map":section}]})).unwrap()).unwrap();
    let inline = String::from_utf8(map(
        serde_json::json!(["b.ts"]),
        serde_json::json!(["// inline recovered"]),
    ))
    .unwrap()
    .replace('{', "%7B")
    .replace('}', "%7D")
    .replace(' ', "%20");
    std::fs::write(
        input.join("inline.js"),
        format!("fetch('/inline');\n//# sourceMappingURL=data:application/json,{inline}"),
    )
    .unwrap();
    let mut opt = options(input.to_string_lossy().into(), temp.path().join("out"));
    opt.offline = true;
    let r = scan(opt, RuntimeCapture::default(), CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(r.recovered_sources.len(), 2, "{:?}", r.diagnostics);
    assert!(
        r.recovered_sources
            .iter()
            .all(|s| s.exported_path.is_some())
    );
}

#[tokio::test]
async fn html_modules_queries_and_origin_credentials() {
    let leaked = Arc::new(AtomicUsize::new(0));
    let leak = leaked.clone();
    let cdn = server(move |request| {
        if request.to_lowercase().contains("authorization:")
            || request.to_lowercase().contains("cookie:")
        {
            leak.fetch_add(1, Ordering::SeqCst);
        }
        (
            200,
            "application/javascript".into(),
            "fetch('/cdn');".into(),
            String::new(),
        )
    })
    .await;
    let cdn_url = cdn.url.clone();
    let hits = Arc::new(AtomicUsize::new(0));
    let got = hits.clone();
    let app=server(move|request|{
        let path=request.lines().next().unwrap().split_whitespace().nth(1).unwrap();
        match path{
            "/"=>(200,"text/html".into(),"<base href='/assets/'><script type='importmap'>{\"imports\":{\"lib\":\"./lib.js\"}}</script><script type='module' src='app.js?v=1'></script>".into(),"Set-Cookie: session=private; Path=/\r\n".into()),
            "/assets/app.js?v=1"=>(200,"application/javascript".into(),format!("import 'lib';import('./lazy.js');fetch('/users');//# sourceMappingURL={}/cdn.js",cdn_url),String::new()),
            "/assets/app.js.map?v=1"=>{got.fetch_add(1,Ordering::SeqCst);(200,"application/json".into(),String::from_utf8(map(serde_json::json!(["src/app.ts"]),serde_json::json!(["const client_secret='privateKey9Abcd123456';"]))).unwrap(),String::new())},
            "/assets/lib.js"|"/assets/lazy.js"=>(200,"application/javascript".into(),"export const ready=true;".into(),String::new()),
            _=>(404,"text/plain".into(),"missing".into(),String::new()),
        }
    }).await;
    let temp = tempfile::tempdir().unwrap();
    let mut opt = options(app.url.clone(), temp.path().join("out"));
    opt.headers
        .insert("Authorization".into(), "Bearer fixture-secret".into());
    let r = scan(opt, RuntimeCapture::default(), CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(leaked.load(Ordering::SeqCst), 0);
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    assert!(
        r.artifacts
            .iter()
            .any(|a| a.location.ends_with("/assets/lazy.js"))
    );
    assert!(
        r.findings
            .iter()
            .any(|f| f.value == "privateKey9Abcd123456")
    );
    assert!(r.modules.iter().any(|m| m.specifier == "lib"));
}

#[tokio::test]
async fn local_origin_fetches_missing_maps_and_offline_makes_zero_requests() {
    let hits = Arc::new(AtomicUsize::new(0));
    let got = hits.clone();
    let http = server(move |request| {
        got.fetch_add(1, Ordering::SeqCst);
        let path = request
            .lines()
            .next()
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap();
        if path == "/assets/app.js.map?v=2" {
            (
                200,
                "application/json".into(),
                String::from_utf8(map(serde_json::json!(["a.ts"]), serde_json::json!([""])))
                    .unwrap(),
                String::new(),
            )
        } else {
            (404, "text/plain".into(), "missing".into(), String::new())
        }
    })
    .await;
    let temp = tempfile::tempdir().unwrap();
    let input = temp.path().join("assets");
    std::fs::create_dir(&input).unwrap();
    std::fs::write(
        input.join("app.js"),
        "fetch('/users');\n//# sourceMappingURL=app.js.map?v=2",
    )
    .unwrap();
    let mut opt = options(input.to_string_lossy().into(), temp.path().join("online"));
    opt.base_url = Some(format!("{}/assets/", http.url));
    let r = scan(
        opt.clone(),
        RuntimeCapture::default(),
        CancellationToken::new(),
    )
    .await
    .unwrap();
    assert_eq!(r.recovered_sources.len(), 1, "{:?}", r.diagnostics);
    let before = hits.load(Ordering::SeqCst);
    opt.offline = true;
    opt.out = temp.path().join("offline");
    scan(opt, RuntimeCapture::default(), CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(hits.load(Ordering::SeqCst), before);
}

#[tokio::test]
async fn analyze_only_limits_cancellation_and_parse_fallback() {
    let temp = tempfile::tempdir().unwrap();
    let input = temp.path().join("bad.js");
    std::fs::write(&input,"const broken = ; // https://internal.test/api\n//# sourceMappingURL=https://no-request.invalid/x.map").unwrap();
    let mut opt = options(input.to_string_lossy().into(), temp.path().join("analyze"));
    opt.offline = true;
    opt.analyze_only = true;
    let r = scan(
        opt.clone(),
        RuntimeCapture::default(),
        CancellationToken::new(),
    )
    .await
    .unwrap();
    assert!(r.coverage.partial);
    assert_eq!(r.artifacts.len(), 1);
    assert!(r.diagnostics.iter().any(|d| d.code == "parse_fallback"));
    opt.out = temp.path().join("limited");
    opt.max_asset_bytes = 4;
    let r = scan(
        opt.clone(),
        RuntimeCapture::default(),
        CancellationToken::new(),
    )
    .await
    .unwrap();
    assert!(r.coverage.partial);
    opt.out = temp.path().join("cancelled");
    let cancel = CancellationToken::new();
    cancel.cancel();
    let r = scan(opt, RuntimeCapture::default(), cancel).await.unwrap();
    assert!(r.coverage.cancelled);
}

#[tokio::test]
async fn redirect_does_not_forward_credentials() {
    let leak = Arc::new(AtomicUsize::new(0));
    let check = leak.clone();
    let external = server(move |r| {
        if r.to_lowercase().contains("authorization:") {
            check.fetch_add(1, Ordering::SeqCst);
        }
        (
            200,
            "application/javascript".into(),
            "fetch('/redirected');".into(),
            String::new(),
        )
    })
    .await;
    let destination = external.url.clone();
    let app = server(move |_| {
        (
            302,
            "text/plain".into(),
            String::new(),
            format!("Location: {destination}/asset.js\r\n"),
        )
    })
    .await;
    let temp = tempfile::tempdir().unwrap();
    let mut opt = options(format!("{}/input.js", app.url), temp.path().join("out"));
    opt.headers
        .insert("Authorization".into(), "Bearer private".into());
    opt.timeout_secs = 2;
    let r = tokio::time::timeout(
        Duration::from_secs(10),
        scan(opt, RuntimeCapture::default(), CancellationToken::new()),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(leak.load(Ordering::SeqCst), 0);
    assert!(!r.artifacts.is_empty());
}

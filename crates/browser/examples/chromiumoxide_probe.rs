//! Adapter spike: verifies whether page-level subscriptions retain worker sources.
use anyhow::Result;
use chromiumoxide::{
    Browser, BrowserConfig,
    cdp::js_protocol::debugger::{EnableParams, EventScriptParsed},
};
use futures::StreamExt;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<()> {
    let path = std::env::args().nth(1).expect("Chrome executable argument");
    let profile = tempfile::tempdir()?;
    let (mut browser, mut handler) = Browser::launch(
        BrowserConfig::builder()
            .chrome_executable(path)
            .user_data_dir(profile.path())
            .build()
            .map_err(|e| anyhow::anyhow!(e))?,
    )
    .await?;
    let driver = tokio::spawn(async move {
        while let Some(result) = handler.next().await {
            if result.is_err() {
                break;
            }
        }
    });
    let page = browser.new_page("about:blank").await?;
    let mut scripts = page.event_listener::<EventScriptParsed>().await?;
    page.execute(EnableParams::default()).await?;
    page.evaluate("globalThis.workerDone=false; const w=new Worker(URL.createObjectURL(new Blob([\"globalThis.workerMarker='worker-source-marker';postMessage('ready')\"],{type:'application/javascript'})));w.onmessage=()=>globalThis.workerDone=true;globalThis.mainMarker='page-source-marker'").await?;
    tokio::time::sleep(Duration::from_secs(2)).await;
    let worker_ran = page
        .evaluate("globalThis.workerDone")
        .await?
        .into_value::<bool>()?;
    let mut worker_sources = 0;
    let mut total_sources = 0;
    while let Ok(Some(event)) =
        tokio::time::timeout(Duration::from_millis(100), scripts.next()).await
    {
        total_sources += 1;
        if event.url.starts_with("blob:") {
            worker_sources += 1;
        }
    }
    println!(
        "{}",
        serde_json::json!({"worker_executed":worker_ran,"page_subscription_scripts":total_sources,"worker_script_sources":worker_sources})
    );
    browser.close().await?;
    browser.wait().await?;
    driver.await?;
    anyhow::ensure!(worker_ran, "worker did not run");
    Ok(())
}

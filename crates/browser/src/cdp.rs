use anyhow::{Context, Result, anyhow, bail};
use futures::{SinkExt, StreamExt};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::sync::{mpsc, oneshot};
use tokio_tungstenite::{
    connect_async_with_config,
    tungstenite::{Message, protocol::WebSocketConfig},
};
use tokio_util::sync::CancellationToken;

struct Command {
    method: String,
    params: Value,
    session: Option<String>,
    reply: oneshot::Sender<Result<Value>>,
}

#[derive(Clone)]
pub struct Cdp {
    commands: mpsc::Sender<Command>,
    pub lost_events: Arc<AtomicUsize>,
    timeout: Duration,
    stop: CancellationToken,
}

impl Cdp {
    pub async fn connect(
        endpoint: &str,
        timeout: Duration,
        max_message: usize,
    ) -> Result<(Self, mpsc::Receiver<Value>)> {
        let config = WebSocketConfig::default()
            .max_message_size(Some(max_message.saturating_mul(2).max(1024 * 1024)))
            .max_frame_size(Some(max_message.saturating_mul(2).max(1024 * 1024)));
        let (socket, _) = tokio::time::timeout(
            timeout,
            connect_async_with_config(endpoint, Some(config), false),
        )
        .await
        .context("CDP connect timeout")??;
        let (commands, mut receiver) = mpsc::channel::<Command>(256);
        let (events, event_receiver) = mpsc::channel(8192);
        let lost_events = Arc::new(AtomicUsize::new(0));
        let lost = lost_events.clone();
        let stop = CancellationToken::new();
        let stopped = stop.clone();
        tokio::spawn(async move {
            let (mut sink, mut source) = socket.split();
            let mut pending = HashMap::new();
            let mut sequence = 0u64;
            loop {
                tokio::select! {
                    _ = stopped.cancelled() => break,
                    command = receiver.recv() => {
                        let Some(command) = command else { break; };
                        sequence += 1;
                        let mut payload = json!({"id":sequence,"method":command.method,"params":command.params});
                        if let Some(session) = command.session { payload["sessionId"] = session.into(); }
                        pending.insert(sequence,command.reply);
                        if sink.send(Message::Text(payload.to_string().into())).await.is_err() { break; }
                    },
                    message = source.next() => {
                        match message {
                            Some(Ok(Message::Text(text))) => {
                                let Ok(value) = serde_json::from_str::<Value>(&text) else { continue; };
                                if let Some(id) = value.get("id").and_then(Value::as_u64) {
                                    if let Some(reply) = pending.remove(&id) {
                                        let result = if let Some(error) = value.get("error") { Err(anyhow!("CDP: {error}")) } else { Ok(value.get("result").cloned().unwrap_or(Value::Null)) };
                                        let _ = reply.send(result);
                                    }
                                } else if events.try_send(value).is_err() { lost.fetch_add(1,Ordering::Relaxed); }
                            },
                            Some(Ok(Message::Ping(data))) => { if sink.send(Message::Pong(data)).await.is_err() { break; } },
                            Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                            _ => {},
                        }
                    }
                }
                pending.retain(|_, reply| !reply.is_closed());
            }
            for (_, reply) in pending {
                let _ = reply.send(Err(anyhow!("CDP connection closed")));
            }
            let _ = sink.close().await;
        });
        Ok((
            Self {
                commands,
                lost_events,
                timeout,
                stop,
            },
            event_receiver,
        ))
    }
    pub async fn command(
        &self,
        session: Option<&str>,
        method: &str,
        params: Value,
    ) -> Result<Value> {
        if std::env::var_os("R3KJ4_CDP_TRACE").is_some() {
            eprintln!("CDP command {session:?} {method}");
        }
        let (reply, response) = oneshot::channel();
        tokio::time::timeout(self.timeout, async {
            self.commands
                .send(Command {
                    method: method.into(),
                    params,
                    session: session.map(str::to_string),
                    reply,
                })
                .await
                .map_err(|_| anyhow!("CDP driver closed"))?;
            response.await.map_err(|_| anyhow!("CDP command dropped"))?
        })
        .await
        .with_context(|| format!("{method} timed out"))?
    }
    pub async fn evaluate(&self, session: &str, expression: String) -> Result<Value> {
        let result = self
            .command(
                Some(session),
                "Runtime.evaluate",
                json!({"expression":expression,"awaitPromise":true,"returnByValue":true}),
            )
            .await?;
        if let Some(exception) = result.get("exceptionDetails") {
            bail!("JavaScript evaluation: {exception}");
        }
        Ok(result["result"]["value"].clone())
    }
    pub fn shutdown(&self) {
        self.stop.cancel();
    }
}

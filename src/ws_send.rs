//! Persistent WebSocket transaction sender extracted from lighter-execd.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;
use tokio_tungstenite::tungstenite::Message;
use tracing::{info, warn};

/// How long one send waits for its answer before it is `Unknown`. A normal
/// answer takes ~4ms; anything near this is a broken path, not a slow one.
pub const ANSWER_TIMEOUT: Duration = Duration::from_millis(500);
/// Keepalive. Lighter closes a client that has sent nothing for ~120s, and
/// the escape trigger's 5s interval is the one already proven live.
pub const PING_EVERY: Duration = Duration::from_secs(5);
/// Ping intervals without any frame or pong before the socket counts as dead.
const DEAD_PINGS: u32 = 3;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// A send that waited longer than this for the socket (it dropped between
/// the connected check and the dequeue, and is reconnecting) is not sent: an
/// IOC priced for a book that has moved on goes out over REST now instead.
pub const MAX_QUEUE_WAIT: Duration = Duration::from_millis(100);
/// The caller's own bound on the whole exchange. Past it the send is
/// Unknown -- it may have gone out -- and the caller resends over REST.
const APP_PONG: &str = r#"{"type":"pong"}"#;
const REPLY_SLACK: Duration = Duration::from_millis(250);
static NEXT_REQUEST_ID: AtomicU64 = AtomicU64::new(1);
const BACKOFF: [u64; 5] = [1, 2, 5, 10, 30];

#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    /// The venue's reply, in the REST response's shape: `code`, `message`,
    /// `tx_hash`, `predicted_execution_time_ms` -- so the caller reads it
    /// exactly as it reads a REST body.
    Answered(Value),
    NotSent(String),
    Unknown(String),
}

fn code_of(v: Option<&Value>) -> Option<i64> {
    match v? {
        Value::Number(n) => n.as_i64(),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

/// The REST-shaped reply for a frame that answers a send, or None for any
/// frame that does not (the `connected` hello, an app-level pong, anything a
/// future server adds).
pub fn answer_of(v: &Value) -> Option<Value> {
    let kind = v.get("type").and_then(Value::as_str).unwrap_or("");
    if let Some(err) = v.get("error").filter(|e| e.is_object()) {
        return Some(json!({
            "code": code_of(err.get("code")).unwrap_or(-1),
            "message": err.get("message").and_then(Value::as_str).unwrap_or("unknown"),
        }));
    }
    if kind == "jsonapi/sendtx" || kind == "error" {
        // Top level is the shape observed (and the one Nautilus Trader's
        // adapter parses); `data` is read too in case the server nests it.
        let field = |k: &str| v.get(k).or_else(|| v.get("data").and_then(|d| d.get(k)));
        let tx_hash = field("tx_hash").and_then(Value::as_str);
        // An ack with a tx_hash and no code is an ack. No code and no hash
        // stays -1, which the caller treats as NO answer, never a rejection.
        let code = code_of(field("code"))
            .or(if tx_hash.is_some() { Some(200) } else { None })
            .unwrap_or(-1);
        let mut out = json!({
            "code": code,
            "message": field("message").and_then(Value::as_str).unwrap_or(""),
        });
        if let Some(h) = tx_hash {
            out["tx_hash"] = json!(h);
        }
        if let Some(t) = field("predicted_execution_time_ms") {
            out["predicted_execution_time_ms"] = t.clone();
        }
        return Some(out);
    }
    None
}

fn is_conclusive(answer: &Value, expected_hash: Option<&str>) -> bool {
    match answer["code"].as_i64() {
        Some(200) => answer["tx_hash"].as_str().is_some_and(|hash| {
            !hash.is_empty()
                && expected_hash
                    .map_or(true, |expected| crate::client::hashes_match(hash, expected))
        }),
        Some(code) => code > 0,
        None => false,
    }
}

struct Job {
    frame: String,
    request_id: String,
    expected_hash: Option<String>,
    reply: oneshot::Sender<Outcome>,
    queued: Instant,
}

#[derive(Default)]
pub struct Stats {
    pub connected: AtomicBool,
    pub answered: AtomicU64,
    pub not_sent: AtomicU64,
    pub unknown: AtomicU64,
    pub connects: AtomicU64,
}

/// One socket, one task, one send at a time. Cheap to clone.
#[derive(Clone)]
pub struct WsSender {
    jobs: mpsc::Sender<Job>,
    pub stats: Arc<Stats>,
    started: Arc<AtomicBool>,
    url: Arc<String>,
    rx: Arc<std::sync::Mutex<Option<mpsc::Receiver<Job>>>>,
    timeout: Duration,
    ping: Duration,
}

impl WsSender {
    /// Inert until the first `start()` or `send()`: a daemon that never sees
    /// a WS order never opens the socket.
    pub fn new(url: String) -> Self {
        Self::with_timing(url, ANSWER_TIMEOUT, PING_EVERY)
    }

    pub fn with_timing(url: String, timeout: Duration, ping: Duration) -> Self {
        let (jobs, rx) = mpsc::channel(64);
        WsSender {
            jobs,
            stats: Arc::new(Stats::default()),
            started: Arc::new(AtomicBool::new(false)),
            url: Arc::new(url),
            rx: Arc::new(std::sync::Mutex::new(Some(rx))),
            timeout,
            ping,
        }
    }

    pub fn is_connected(&self) -> bool {
        self.stats.connected.load(Ordering::Relaxed)
    }

    pub fn start(&self) {
        if self.started.swap(true, Ordering::SeqCst) {
            return;
        }
        let rx = self.rx.lock().unwrap().take().expect("receiver taken once");
        let (url, stats, timeout, ping) = (
            self.url.clone(),
            self.stats.clone(),
            self.timeout,
            self.ping,
        );
        tokio::spawn(run(url, rx, stats, timeout, ping));
    }

    /// Send one signed tx. `tx_info` is the same JSON string REST posts; the
    /// socket takes it as an object.
    pub async fn send(&self, tx_type: u8, tx_info: &str, expected_hash: Option<&str>) -> Outcome {
        self.start();
        if !self.is_connected() {
            self.stats.not_sent.fetch_add(1, Ordering::Relaxed);
            return Outcome::NotSent("ws not connected".into());
        }
        let info: Value = match serde_json::from_str(tx_info) {
            Ok(v) => v,
            Err(e) => return Outcome::NotSent(format!("tx_info is not JSON: {e}")),
        };
        let request_id = NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed).to_string();
        let frame = json!({"type": "jsonapi/sendtx",
                           "data": {"id": request_id, "tx_type": tx_type, "tx_info": info}})
        .to_string();
        let (reply, rx) = oneshot::channel();
        if self
            .jobs
            .send(Job {
                frame,
                request_id,
                expected_hash: expected_hash.map(str::to_owned),
                reply,
                queued: Instant::now(),
            })
            .await
            .is_err()
        {
            self.stats.not_sent.fetch_add(1, Ordering::Relaxed);
            return Outcome::NotSent("ws task gone".into());
        }
        let out = match tokio::time::timeout(self.timeout + REPLY_SLACK, rx).await {
            Ok(Ok(o)) => o,
            Ok(Err(_)) => Outcome::Unknown("ws task dropped the reply".into()),
            Err(_) => Outcome::Unknown("no reply from the ws task in time".into()),
        };
        let counter = match out {
            Outcome::Answered(_) => &self.stats.answered,
            Outcome::NotSent(_) => &self.stats.not_sent,
            Outcome::Unknown(_) => &self.stats.unknown,
        };
        counter.fetch_add(1, Ordering::Relaxed);
        out
    }
}

type Ws =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn run(
    url: Arc<String>,
    mut rx: mpsc::Receiver<Job>,
    stats: Arc<Stats>,
    timeout: Duration,
    ping: Duration,
) {
    let mut attempt = 0usize;
    while !rx.is_closed() {
        let conn = tokio::time::timeout(
            CONNECT_TIMEOUT,
            tokio_tungstenite::connect_async(url.as_str()),
        )
        .await;
        let mut ws = match conn {
            Ok(Ok((ws, _))) => ws,
            other => {
                let err = match other {
                    Ok(Err(e)) => e.to_string(),
                    _ => "connect timeout".to_string(),
                };
                warn!(url = %url, error = %err, "ws send: connect failed");
                // Anything queued meanwhile never left: REST is safe for it.
                while let Ok(job) = rx.try_recv() {
                    let _ = job.reply.send(Outcome::NotSent("ws connecting".into()));
                }
                let wait = BACKOFF[attempt.min(BACKOFF.len() - 1)];
                attempt += 1;
                tokio::time::sleep(Duration::from_secs(wait)).await;
                continue;
            }
        };
        attempt = 0;
        stats.connects.fetch_add(1, Ordering::Relaxed);
        stats.connected.store(true, Ordering::Relaxed);
        info!(url = %url, "ws send: connected");
        let why = serve(&mut ws, &mut rx, timeout, ping).await;
        stats.connected.store(false, Ordering::Relaxed);
        let _ = tokio::time::timeout(timeout, ws.close(None)).await;
        warn!(url = %url, reason = %why, "ws send: connection closed");
        // Jobs queued behind the one that ended the connection never left.
        while let Ok(job) = rx.try_recv() {
            let _ = job.reply.send(Outcome::NotSent("ws reconnecting".into()));
        }
        if rx.is_closed() {
            return;
        }
    }
}

/// Serve one connection until it must be dropped; returns why.
async fn serve(
    ws: &mut Ws,
    rx: &mut mpsc::Receiver<Job>,
    timeout: Duration,
    ping: Duration,
) -> String {
    let mut heard = Instant::now();
    let mut keepalive = tokio::time::interval(ping);
    keepalive.tick().await;
    loop {
        tokio::select! {
            job = rx.recv() => {
                let Some(job) = job else { return "sender dropped".into() };
                if job.reply.is_closed() || job.queued.elapsed() > MAX_QUEUE_WAIT {
                    let _ = job.reply.send(Outcome::NotSent("queued too long for the socket".into()));
                    continue;
                }
                let deadline = Instant::now() + timeout;
                match tokio::time::timeout_at(deadline, ws.send(Message::Text(job.frame))).await {
                    Ok(Ok(())) => {}
                    other => {
                        let error = match other {
                            Ok(Err(e)) => format!("write failed: {e}"),
                            _ => "write timed out".into(),
                        };
                        let _ = job.reply.send(Outcome::Unknown(error.clone()));
                        return error;
                    }
                }
                loop {
                    match tokio::time::timeout_at(deadline, ws.next()).await {
                        Err(_) => {
                            let _ = job.reply.send(Outcome::Unknown("no answer within timeout".into()));
                            // Its late answer must not be read as the next send's.
                            return "send timed out".into();
                        }
                        Ok(None) => {
                            let _ = job.reply.send(Outcome::Unknown("socket closed".into()));
                            return "closed while a send was in flight".into();
                        }
                        Ok(Some(Err(e))) => {
                            let _ = job.reply.send(Outcome::Unknown(format!("read failed: {e}")));
                            return format!("read failed: {e}");
                        }
                        Ok(Some(Ok(msg))) => {
                            heard = Instant::now();
                            if let Message::Text(t) = &msg {
                                if let Ok(frame) = serde_json::from_str::<Value>(t) {
                                    if frame["type"] == "ping" {
                                        let pong = ws.send(Message::Text(APP_PONG.into()));
                                        if !matches!(tokio::time::timeout_at(deadline, pong).await, Ok(Ok(()))) {
                                            let reason = "application pong failed while awaiting acknowledgment";
                                            let _ = job.reply.send(Outcome::Unknown(reason.into()));
                                            return reason.into();
                                        }
                                        continue;
                                    }
                                    if let Some(answer) = answer_of(&frame) {
                                        let id = [&frame["id"], &frame["data"]["id"], &frame["error"]["id"]]
                                            .into_iter()
                                            .find(|id| !id.is_null());
                                        let matched_id = id.and_then(Value::as_str) == Some(job.request_id.as_str());
                                        if id.is_some() && !matched_id {
                                            continue;
                                        }
                                        // A bare error can concern the connection rather than this order.
                                        if !matched_id && frame["type"] != "jsonapi/sendtx" {
                                            continue;
                                        }
                                        if !is_conclusive(&answer, job.expected_hash.as_deref()) {
                                            let reason = "ambiguous WebSocket acknowledgment";
                                            let _ = job.reply.send(Outcome::Unknown(reason.into()));
                                            return reason.into();
                                        }
                                        let _ = job.reply.send(Outcome::Answered(answer));
                                        break;
                                    }
                                }
                            }
                            if let Message::Close(_) = msg {
                                let _ = job.reply.send(Outcome::Unknown("server closed".into()));
                                return "server closed while a send was in flight".into();
                            }
                        }
                    }
                }
            }
            _ = keepalive.tick() => {
                if heard.elapsed() > ping * DEAD_PINGS {
                    return "no frame or pong for 3 pings".into();
                }
                let ping = ws.send(Message::Ping(Vec::new()));
                if !matches!(tokio::time::timeout(timeout, ping).await, Ok(Ok(()))) {
                    return "protocol ping failed".into();
                }
            }
            msg = ws.next() => {
                match msg {
                    None => return "closed".into(),
                    Some(Err(e)) => return format!("read failed: {e}"),
                    Some(Ok(Message::Close(_))) => return "server closed".into(),
                    Some(Ok(Message::Text(t))) => {
                        heard = Instant::now();
                        // The hello, or something we did not ask for. An
                        // answer here would belong to no send -- worth a line.
                        if let Ok(frame) = serde_json::from_str::<Value>(&t) {
                            if frame["type"] == "ping" {
                                let pong = ws.send(Message::Text(APP_PONG.into()));
                                if !matches!(tokio::time::timeout(timeout, pong).await, Ok(Ok(()))) {
                                    return "idle application pong failed".into();
                                }
                            } else if answer_of(&frame).is_some() {
                                return "answer with no send in flight".into();
                            }
                        }
                    }
                    Some(Ok(_)) => heard = Instant::now(),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn an_ack_reads_like_a_rest_200() {
        let a =
            answer_of(&json!({"type": "jsonapi/sendtx", "code": 200, "tx_hash": "ab"})).unwrap();
        assert_eq!(a["code"], 200);
        assert_eq!(a["tx_hash"], "ab");
        let a =
            answer_of(&json!({"type": "jsonapi/sendtx", "code": "200", "tx_hash": "ab"})).unwrap();
        assert_eq!(a["code"], 200);
        let a = answer_of(&json!({"type": "jsonapi/sendtx", "tx_hash": "ab"})).unwrap();
        assert_eq!(a["code"], 200);
    }

    #[test]
    fn every_rejection_shape_reads_like_a_rest_rejection() {
        for (v, code, msg) in [
            (
                json!({"error": {"code": 21702, "message": "invalid price"}}),
                21702,
                "invalid price",
            ),
            (
                json!({"id": "x", "error": {"code": 21104, "message": "invalid nonce"}}),
                21104,
                "invalid nonce",
            ),
            (
                json!({"type": "jsonapi/sendtx", "code": 21727, "message": "invalid client order index"}),
                21727,
                "invalid client order index",
            ),
            (
                json!({"type": "error", "code": 30009, "message": "rate limit exceeded"}),
                30009,
                "rate limit exceeded",
            ),
        ] {
            let a = answer_of(&v).unwrap();
            assert_eq!(a["code"], code);
            assert_eq!(a["message"], msg);
        }
    }

    #[test]
    fn an_ack_nested_under_data_is_still_an_ack() {
        let a = answer_of(&json!({"type": "jsonapi/sendtx",
                                  "data": {"code": 200, "tx_hash": "ab"}}))
        .unwrap();
        assert_eq!(a["code"], 200);
        assert_eq!(a["tx_hash"], "ab");
    }

    #[tokio::test]
    async fn an_answer_with_no_readable_code_is_unknown_never_a_rejection() {
        let (url, _) =
            server(|_| Some(r#"{"type":"jsonapi/sendtx","something":"new"}"#.into())).await;
        let s = WsSender::new(url);
        connected(&s).await;
        assert!(matches!(s.send(14, "{}", None).await, Outcome::Unknown(_)));
        tokio::time::timeout(Duration::from_secs(2), async {
            while s.stats.connects.load(Ordering::Relaxed) < 2 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
    }

    #[test]
    fn frames_that_answer_nothing_are_not_answers() {
        assert!(answer_of(&json!({"type": "connected", "session_id": "s"})).is_none());
        assert!(answer_of(&json!({"type": "pong"})).is_none());
        assert!(answer_of(&json!({"type": "update/ticker", "channel": "ticker:1"})).is_none());
    }

    // ---- against a real local socket (plain ws://, no TLS)

    /// A server that answers each text frame with `answer(n)` (None = stay
    /// silent) and records what it received.
    async fn server<F>(answer: F) -> (String, Arc<std::sync::Mutex<Vec<String>>>)
    where
        F: Fn(usize) -> Option<String> + Send + Sync + 'static,
    {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", l.local_addr().unwrap());
        let got = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (g, answer) = (got.clone(), Arc::new(answer));
        tokio::spawn(async move {
            loop {
                let (s, _) = l.accept().await.unwrap();
                let (g, answer) = (g.clone(), answer.clone());
                tokio::spawn(async move {
                    let mut ws = tokio_tungstenite::accept_async(s).await.unwrap();
                    ws.send(Message::Text(
                        r#"{"type":"connected","session_id":"t"}"#.into(),
                    ))
                    .await
                    .unwrap();
                    while let Some(Ok(m)) = ws.next().await {
                        if let Message::Text(t) = m {
                            let n = {
                                let mut g = g.lock().unwrap();
                                g.push(t);
                                g.len()
                            };
                            if let Some(a) = answer(n) {
                                if ws.send(Message::Text(a)).await.is_err() {
                                    return;
                                }
                            }
                        }
                    }
                });
            }
        });
        (url, got)
    }

    async fn connected(s: &WsSender) {
        s.start();
        for _ in 0..1000 {
            if s.stats.connected.load(Ordering::Relaxed) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("never connected");
    }

    #[tokio::test]
    async fn a_send_before_the_socket_is_up_is_not_sent() {
        let (url, got) = server(|_| None).await;
        let s = WsSender::new(url);
        assert!(matches!(s.send(14, "{}", None).await, Outcome::NotSent(_)));
        connected(&s).await;
        assert!(got.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn the_frame_carries_tx_info_as_an_object_and_the_ack_comes_back() {
        let (url, got) =
            server(|_| Some(r#"{"type":"jsonapi/sendtx","code":200,"tx_hash":"h1"}"#.into())).await;
        let s = WsSender::new(url);
        connected(&s).await;
        let out = s.send(14, r#"{"Nonce":7}"#, None).await;
        assert_eq!(
            out,
            Outcome::Answered(json!({"code": 200, "message": "", "tx_hash": "h1"}))
        );
        let sent: Value = serde_json::from_str(&got.lock().unwrap()[0]).unwrap();
        assert_eq!(sent["type"], "jsonapi/sendtx");
        assert!(sent["data"]["id"].as_str().is_some_and(|id| !id.is_empty()));
        assert_eq!(sent["data"]["tx_type"], 14);
        assert_eq!(sent["data"]["tx_info"], json!({"Nonce": 7}));
    }

    #[tokio::test]
    async fn concurrent_sends_each_get_their_own_answer() {
        let (url, _) = server(|n| {
            Some(format!(
                r#"{{"type":"jsonapi/sendtx","code":200,"tx_hash":"h{n}"}}"#
            ))
        })
        .await;
        let s = WsSender::new(url);
        connected(&s).await;
        let (a, b) = tokio::join!(s.send(14, "{}", None), s.send(14, "{}", None));
        let mut hashes: Vec<String> = [a, b]
            .into_iter()
            .map(|o| match o {
                Outcome::Answered(v) => v["tx_hash"].as_str().unwrap().to_string(),
                other => panic!("{other:?}"),
            })
            .collect();
        hashes.sort();
        assert_eq!(hashes, vec!["h1", "h2"]);
    }

    #[tokio::test]
    async fn no_answer_is_unknown_and_the_late_answer_cannot_reach_the_next_send() {
        // Silent on the first send, answers the second.
        let (url, got) = server(|n| {
            if n == 1 {
                None
            } else {
                Some(format!(
                    r#"{{"type":"jsonapi/sendtx","code":200,"tx_hash":"h{n}"}}"#
                ))
            }
        })
        .await;
        let s = WsSender::with_timing(url, Duration::from_millis(100), PING_EVERY);
        connected(&s).await;
        assert!(matches!(s.send(14, "{}", None).await, Outcome::Unknown(_)));
        // The socket was dropped; a send now either finds it down (NotSent)
        // or, once reconnected, gets its own answer -- never "h1".
        let mut out = s.send(14, "{}", None).await;
        for _ in 0..100 {
            if !matches!(out, Outcome::NotSent(_)) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
            out = s.send(14, "{}", None).await;
        }
        assert_eq!(
            out,
            Outcome::Answered(json!({"code": 200, "message": "", "tx_hash": "h2"}))
        );
        assert_eq!(s.stats.connects.load(Ordering::Relaxed), 2);
        assert_eq!(got.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn an_error_with_the_matching_request_id_rejects_the_order() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(socket).await.unwrap();
            let sent = ws.next().await.unwrap().unwrap().into_text().unwrap();
            let sent: Value = serde_json::from_str(&sent).unwrap();
            let reply = json!({"id": sent["data"]["id"], "error": {"code": 21702, "message": "invalid price"}});
            ws.send(Message::Text(reply.to_string())).await.unwrap();
        });
        let s = WsSender::new(url);
        connected(&s).await;
        assert_eq!(
            s.send(14, "{}", None).await,
            Outcome::Answered(json!({"code": 21702, "message": "invalid price"}))
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn a_queued_send_older_than_the_limit_goes_back_unsent() {
        let (url, got) = server(|n| {
            Some(format!(
                r#"{{"type":"jsonapi/sendtx","code":200,"tx_hash":"h{n}"}}"#
            ))
        })
        .await;
        let s = WsSender::new(url);
        connected(&s).await;
        let (reply, rx) = oneshot::channel();
        let frame =
            json!({"type": "jsonapi/sendtx", "data": {"tx_type": 14, "tx_info": {}}}).to_string();
        s.jobs
            .send(Job {
                frame,
                request_id: "stale".into(),
                expected_hash: None,
                reply,
                queued: Instant::now() - Duration::from_millis(150),
            })
            .await
            .unwrap();
        assert!(matches!(rx.await.unwrap(), Outcome::NotSent(_)));
        assert!(got.lock().unwrap().is_empty());
        // ...and the socket is still serving.
        assert!(matches!(s.send(14, "{}", None).await, Outcome::Answered(_)));
    }

    #[tokio::test]
    async fn application_pings_are_answered_when_idle_and_during_submission() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let (idle_pong, idle_pong_received) = oneshot::channel();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(socket).await.unwrap();
            let ping = Message::Text(r#"{"type":"ping"}"#.into());
            let pong = Message::Text(APP_PONG.into());
            ws.send(ping.clone()).await.unwrap();
            assert_eq!(ws.next().await.unwrap().unwrap(), pong);
            idle_pong.send(()).unwrap();

            let order = ws.next().await.unwrap().unwrap().into_text().unwrap();
            let order: Value = serde_json::from_str(&order).unwrap();
            assert_eq!(order["type"], "jsonapi/sendtx");
            ws.send(ping).await.unwrap();
            assert_eq!(ws.next().await.unwrap().unwrap(), pong);
            ws.send(Message::Text(
                r#"{"type":"jsonapi/sendtx","code":200,"tx_hash":"abc"}"#.into(),
            ))
            .await
            .unwrap();
        });
        let s = WsSender::new(url);
        connected(&s).await;
        tokio::time::timeout(Duration::from_secs(2), idle_pong_received)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            s.send(14, "{}", Some("abc")).await,
            Outcome::Answered(_)
        ));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn connection_error_must_not_override_matching_transaction_ack() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(socket).await.unwrap();
            let request = ws.next().await.unwrap().unwrap().into_text().unwrap();
            let request: Value = serde_json::from_str(&request).unwrap();
            let id = request["data"]["id"].as_str().unwrap();
            let stale = json!({"id": format!("{id}-stale"), "error": {"code": 21702, "message": "invalid price"}});
            ws.send(Message::Text(stale.to_string())).await.unwrap();
            ws.send(Message::Text(
                r#"{"error":{"code":23000,"message":"Too Many Requests"}}"#.into(),
            ))
            .await
            .unwrap();
            ws.send(Message::Text(
                r#"{"type":"jsonapi/sendtx","code":200,"tx_hash":"abc"}"#.into(),
            ))
            .await
            .unwrap();
        });
        let sender = WsSender::new(url);
        connected(&sender).await;
        let outcome = sender.send(14, "{}", Some("abc")).await;
        server.await.unwrap();
        assert!(
            matches!(outcome, Outcome::Answered(ref reply) if reply["tx_hash"] == "abc"),
            "matching order acknowledgment was superseded by {outcome:?}"
        );
    }
    #[tokio::test]
    async fn a_quiet_socket_is_pinged() {
        // The server never sends anything after the hello; the client must
        // keep the connection alive by pinging (tungstenite answers pongs).
        let (url, _) = server(|_| None).await;
        let s = WsSender::with_timing(url, ANSWER_TIMEOUT, Duration::from_millis(30));
        connected(&s).await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(s.stats.connected.load(Ordering::Relaxed));
        assert_eq!(s.stats.connects.load(Ordering::Relaxed), 1);
    }
}

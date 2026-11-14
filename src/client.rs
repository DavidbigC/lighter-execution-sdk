use std::time::{Duration, SystemTime, UNIX_EPOCH};

use reqwest::Url;
use serde_json::Value;
use tokio::sync::Mutex;

use crate::{Error, LimitOrder, SignedTransaction, Signer};

const HTTP_TIMEOUT: Duration = Duration::from_secs(5);
// Match the Go SDK's ten-minute default with a one-second clock margin.
const TRANSACTION_TTL_MS: i64 = 599_000;

/// The transport that returned an acknowledgment.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Route {
    Rest,
    WebSocket,
    RestFallback,
    WebSocketThenRest,
}

/// Lighter acknowledged the transaction. Fill confirmation is a separate step.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Receipt {
    pub tx_hash: String,
    pub nonce: i64,
    pub route: Route,
    pub predicted_execution_time_ms: Option<i64>,
}

#[derive(Default)]
enum NonceState {
    #[default]
    Cold,
    Ready(i64),
    Unresolved {
        nonce: i64,
        tx_hash: String,
    },
}

/// Execution for one account/key pair. Share a client between tasks to
/// submit in nonce order. Use distinct API keys for independent writers.
pub struct Client {
    signer: Signer,
    http: reqwest::Client,
    base: Url,
    nonce: Mutex<NonceState>,
    #[cfg(feature = "websocket")]
    ws: Option<crate::ws_send::WsSender>,
}

impl Client {
    /// Use REST for this signer's network.
    pub fn new(signer: Signer) -> Result<Self, Error> {
        let base = Url::parse(signer.network().rest_url()).expect("valid network URL");
        let http = reqwest::Client::builder()
            .timeout(HTTP_TIMEOUT)
            .retry(reqwest::retry::never())
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(Error::HttpClient)?;
        Ok(Self {
            signer,
            http,
            base,
            nonce: Mutex::default(),
            #[cfg(feature = "websocket")]
            ws: None,
        })
    }

    /// Prefer a persistent submission socket. A disconnected socket falls back to REST.
    #[cfg(feature = "websocket")]
    pub fn with_websocket(mut self) -> Self {
        self.ws = Some(crate::ws_send::WsSender::new(
            self.signer.network().websocket_url().into(),
        ));
        self
    }

    /// Start connecting the submission socket during startup. Requires a Tokio runtime.
    #[cfg(feature = "websocket")]
    pub fn warm_websocket(&self) {
        if let Some(ws) = &self.ws {
            ws.start();
        }
    }

    /// Fetch the first nonce before the latency-sensitive path.
    pub async fn warm_nonce(&self) -> Result<(), Error> {
        let mut state = self.nonce.lock().await;
        if matches!(*state, NonceState::Cold) {
            *state = NonceState::Ready(self.fetch_nonce().await?);
        }
        match &*state {
            NonceState::Unresolved { nonce, tx_hash } => Err(Error::UnresolvedNonce {
                nonce: *nonce,
                tx_hash: tx_hash.clone(),
            }),
            _ => Ok(()),
        }
    }

    /// Allow submissions again after checking the uncertain transaction at the venue.
    /// Returns false if this transaction is no longer the one awaiting reconciliation.
    pub async fn resume_after_reconciliation(&self, nonce: i64, tx_hash: &str) -> bool {
        let mut state = self.nonce.lock().await;
        if matches!(&*state, NonceState::Unresolved { nonce: pending, tx_hash: hash }
            if *pending == nonce && hashes_match(tx_hash, hash))
        {
            *state = NonceState::Cold;
            true
        } else {
            false
        }
    }

    pub async fn place_order(&self, order: &LimitOrder) -> Result<Receipt, Error> {
        self.execute(|nonce, expiry| self.signer.sign_order(order, nonce, expiry))
            .await
    }

    /// Cancel by Lighter order index or by a nonzero client order index.
    pub async fn cancel_order(&self, market_id: i64, order_index: i64) -> Result<Receipt, Error> {
        self.execute(|nonce, expiry| {
            self.signer
                .sign_cancel(market_id, order_index, nonce, expiry)
        })
        .await
    }

    pub async fn cancel_all(&self) -> Result<Receipt, Error> {
        self.execute(|nonce, expiry| self.signer.sign_cancel_all(nonce, expiry))
            .await
    }

    async fn execute(
        &self,
        sign: impl FnOnce(i64, i64) -> Result<SignedTransaction, Error>,
    ) -> Result<Receipt, Error> {
        let mut state = self.nonce.lock().await;
        let nonce = match &*state {
            NonceState::Ready(nonce) => *nonce,
            NonceState::Cold => self.fetch_nonce().await?,
            NonceState::Unresolved { nonce, tx_hash } => {
                return Err(Error::UnresolvedNonce {
                    nonce: *nonce,
                    tx_hash: tx_hash.clone(),
                })
            }
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Invalid("system clock is before the Unix epoch"))?
            .as_millis() as i64;
        let tx = sign(nonce, now + TRANSACTION_TTL_MS)?;
        // This state also survives cancellation of the caller's future during submission.
        *state = NonceState::Unresolved {
            nonce,
            tx_hash: tx.tx_hash().into(),
        };
        let result = self.submit(&tx).await;
        match &result {
            Ok(_) => {
                *state = nonce
                    .checked_add(1)
                    .map_or(NonceState::Cold, NonceState::Ready);
            }
            Err(Error::Rejected { .. }) => *state = NonceState::Cold,
            Err(_) => {}
        }
        result
    }

    async fn fetch_nonce(&self) -> Result<i64, Error> {
        let url = self
            .base
            .join("/api/v1/nextNonce")
            .expect("valid endpoint path");
        let value = self
            .http
            .get(url)
            .query(&[
                ("account_index", self.signer.account_index.to_string()),
                ("api_key_index", self.signer.api_key_index.to_string()),
            ])
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(|e| Error::NonceLookup(e.to_string()))?
            .json::<Value>()
            .await
            .map_err(|e| Error::NonceLookup(e.to_string()))?;
        value["nonce"]
            .as_i64()
            .filter(|n| *n >= 0)
            .ok_or_else(|| Error::NonceLookup("response lacked a usable nonce".into()))
    }

    async fn submit(&self, tx: &SignedTransaction) -> Result<Receipt, Error> {
        let tx_info = tx.tx_info().to_string();
        #[cfg(feature = "websocket")]
        if let Some(ws) = &self.ws {
            use crate::ws_send::Outcome;
            return match ws.send(tx.tx_type(), &tx_info, Some(tx.tx_hash())).await {
                Outcome::Answered(value) => receipt(&value, tx, Route::WebSocket),
                Outcome::NotSent(_) => self.submit_rest(tx, &tx_info, Route::RestFallback).await,
                Outcome::Unknown(reason) => self
                    .submit_rest(tx, &tx_info, Route::WebSocketThenRest)
                    .await
                    .map_err(|rest| Error::Unknown {
                        nonce: tx.nonce(),
                        tx_hash: tx.tx_hash().into(),
                        detail: format!("WebSocket: {reason}; REST replay: {rest}"),
                    }),
            };
        }
        self.submit_rest(tx, &tx_info, Route::Rest).await
    }

    async fn submit_rest(
        &self,
        tx: &SignedTransaction,
        tx_info: &str,
        route: Route,
    ) -> Result<Receipt, Error> {
        let nonce = tx.nonce();
        let unknown = |detail| Error::Unknown {
            nonce,
            tx_hash: tx.tx_hash().into(),
            detail,
        };
        let url = self
            .base
            .join("/api/v1/sendTx")
            .expect("valid endpoint path");
        let tx_type = tx.tx_type().to_string();
        let response = self
            .http
            .post(url)
            .form(&[
                ("tx_type", tx_type.as_str()),
                ("tx_info", tx_info),
                ("price_protection", "true"),
            ])
            .send()
            .await
            .map_err(|e| unknown(e.to_string()))?;
        let status = response.status();
        if status.is_server_error() || status.is_redirection() {
            return Err(unknown(format!("HTTP {status}")));
        }
        let value: Value = response.json().await.map_err(|e| unknown(e.to_string()))?;
        let acknowledgment = receipt(&value, tx, route)?;
        if !status.is_success() {
            return Err(unknown(format!(
                "acknowledgment received with HTTP {status}"
            )));
        }
        Ok(acknowledgment)
    }
}

pub(crate) fn hashes_match(actual: &str, expected: &str) -> bool {
    actual
        .strip_prefix("0x")
        .unwrap_or(actual)
        .eq_ignore_ascii_case(expected)
}

fn receipt(value: &Value, tx: &SignedTransaction, route: Route) -> Result<Receipt, Error> {
    let nonce = tx.nonce();
    let code = value["code"]
        .as_i64()
        .or_else(|| value["code"].as_str()?.parse().ok());
    if let Some(code) = code.filter(|code| *code > 0 && *code != 200) {
        return Err(Error::Rejected {
            code,
            message: value["message"].as_str().unwrap_or_default().into(),
        });
    }
    if let (Some(200), Some(hash)) = (
        code,
        value["tx_hash"]
            .as_str()
            .filter(|h| hashes_match(h, tx.tx_hash())),
    ) {
        return Ok(Receipt {
            tx_hash: hash.into(),
            nonce,
            route,
            predicted_execution_time_ms: value["predicted_execution_time_ms"].as_i64(),
        });
    }
    Err(Error::Unknown {
        nonce,
        tx_hash: tx.tx_hash().into(),
        detail: "response lacked an acknowledgment for the signed transaction".into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Network, Side, TimeInForce};
    use serde_json::json;
    use std::collections::VecDeque;
    use tokio::{
        io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
        net::TcpListener,
        task::JoinHandle,
    };

    const TEST_KEY: &str =
        "01000000000000000000000000000000000000000000000000000000000000000000000000000000";
    const ORDER: LimitOrder = LimitOrder {
        market_id: 1,
        side: Side::Buy,
        size_ticks: 1000,
        price_ticks: 750_000,
        time_in_force: TimeInForce::Ioc,
        reduce_only: false,
        client_order_index: 123,
    };

    struct Request {
        line: String,
        form: Vec<(String, String)>,
    }

    impl Request {
        fn signed_payload(&self) -> Value {
            let data = self.form.iter().find(|(key, _)| key == "tx_info").unwrap();
            serde_json::from_str(&data.1).unwrap()
        }

        fn tx_type(&self) -> &str {
            &self
                .form
                .iter()
                .find(|(key, _)| key == "tx_type")
                .unwrap()
                .1
        }
    }

    async fn http_fixture(responses: Vec<Option<Value>>) -> (Client, JoinHandle<Vec<Request>>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let base = Url::parse(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
        let signer = Signer::new(Network::Main, 41, 3, TEST_KEY).unwrap();
        let mut client = Client::new(signer).unwrap();
        client.base = base;
        let task = tokio::spawn(async move {
            let mut requests = Vec::new();
            let mut responses = VecDeque::from(responses);
            while let Some(response) = responses.pop_front() {
                let (socket, _) = listener.accept().await.unwrap();
                let mut stream = BufReader::new(socket);
                let mut line = String::new();
                stream.read_line(&mut line).await.unwrap();
                let mut length = 0;
                loop {
                    let mut header = String::new();
                    assert_ne!(stream.read_line(&mut header).await.unwrap(), 0);
                    if header == "\r\n" {
                        break;
                    }
                    if let Some(number) =
                        header.to_ascii_lowercase().strip_prefix("content-length:")
                    {
                        length = number.trim().parse().unwrap();
                    }
                }
                let mut body = vec![0; length];
                stream.read_exact(&mut body).await.unwrap();
                let query = Url::parse("http://localhost")
                    .map(|mut url| {
                        url.set_query(Some(std::str::from_utf8(&body).unwrap()));
                        url
                    })
                    .unwrap();
                requests.push(Request {
                    line,
                    form: query.query_pairs().into_owned().collect(),
                });
                if let Some(mut response) = response {
                    if response["tx_hash"] == "matching" {
                        let signer = Signer::new(Network::Main, 41, 3, TEST_KEY).unwrap();
                        let request = requests.last().unwrap();
                        let tx = request.signed_payload();
                        let nonce = tx["Nonce"].as_i64().unwrap();
                        let expiry = tx["ExpiredAt"].as_i64().unwrap();
                        let signed = match request.tx_type() {
                            "14" => signer.sign_order(&ORDER, nonce, expiry),
                            "15" => signer.sign_cancel(1, 123, nonce, expiry),
                            "16" => signer.sign_cancel_all(nonce, expiry),
                            other => panic!("unexpected tx type {other}"),
                        }
                        .unwrap();
                        response["tx_hash"] = json!(signed.tx_hash());
                    }
                    let body = response.to_string();
                    let output = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    stream.write_all(output.as_bytes()).await.unwrap();
                }
            }
            requests
        });
        (client, task)
    }

    #[tokio::test]
    async fn concurrent_place_and_cancel_share_an_ordered_nonce_sequence() {
        let (client, requests) = http_fixture(vec![
            Some(json!({"nonce": 21})),
            Some(json!({"code": 200, "tx_hash": "matching"})),
            Some(json!({"code": 200, "tx_hash": "matching"})),
        ])
        .await;

        client.warm_nonce().await.unwrap();
        let (place, cancel) = tokio::join!(client.place_order(&ORDER), client.cancel_all());
        assert_eq!(place.unwrap().nonce, 21);
        assert_eq!(cancel.unwrap().nonce, 22);

        let requests = requests.await.unwrap();
        assert!(requests[0]
            .line
            .starts_with("GET /api/v1/nextNonce?account_index=41&api_key_index=3 "));
        assert!(requests[1].line.starts_with("POST /api/v1/sendTx "));
        assert_eq!(requests[1].tx_type(), "14");
        assert_eq!(requests[1].signed_payload()["Nonce"], 21);
        assert_eq!(requests[1].signed_payload()["ClientOrderIndex"], 123);
        assert_eq!(requests[2].tx_type(), "16");
        assert_eq!(requests[2].signed_payload()["Nonce"], 22);
    }

    #[tokio::test]
    async fn explicit_rejection_refreshes_nonce_before_the_next_transaction() {
        let (client, requests) = http_fixture(vec![
            Some(json!({"nonce": 21})),
            Some(json!({"code": 21104, "message": "invalid nonce"})),
            Some(json!({"nonce": 27})),
            Some(json!({"code": 200, "tx_hash": "matching"})),
        ])
        .await;
        assert!(matches!(
            client.place_order(&ORDER).await,
            Err(Error::Rejected { code: 21104, .. })
        ));
        assert_eq!(client.cancel_order(1, 123).await.unwrap().nonce, 27);
        let requests = requests.await.unwrap();
        assert!(requests[2].line.starts_with("GET /api/v1/nextNonce?"));
        assert_eq!(requests[3].tx_type(), "15");
        assert_eq!(requests[3].signed_payload()["Index"], 123);
    }

    #[tokio::test]
    async fn dropped_acknowledgment_requires_reconciliation() {
        let (client, requests) = http_fixture(vec![
            Some(json!({"nonce": 21})),
            None,
            Some(json!({"nonce": 22})),
            Some(json!({"code": 200, "tx_hash": "matching"})),
        ])
        .await;
        let Err(Error::Unknown {
            nonce: 21, tx_hash, ..
        }) = client.place_order(&ORDER).await
        else {
            panic!("expected unresolved submission");
        };
        assert!(matches!(
            client.cancel_all().await,
            Err(Error::UnresolvedNonce { nonce: 21, .. })
        ));
        assert!(!client.resume_after_reconciliation(22, &tx_hash).await);
        assert!(client.resume_after_reconciliation(21, &tx_hash).await);
        assert_eq!(client.cancel_all().await.unwrap().nonce, 22);
        let requests = requests.await.unwrap();
        assert_eq!(requests[1].signed_payload()["Nonce"], 21);
        assert!(requests[2].line.starts_with("GET /api/v1/nextNonce?"));
    }

    #[tokio::test]
    async fn unrelated_acknowledgment_preserves_the_expected_hash_for_reconciliation() {
        let (client, requests) = http_fixture(vec![
            Some(json!({"nonce": 21})),
            Some(json!({"code": 200, "tx_hash": "different-order"})),
        ])
        .await;
        let Error::Unknown { nonce, tx_hash, .. } = client.place_order(&ORDER).await.unwrap_err()
        else {
            panic!("mismatched acknowledgment was treated as accepted")
        };
        assert_eq!(nonce, 21);
        assert_eq!(tx_hash.len(), 80);
        match client.cancel_all().await.unwrap_err() {
            Error::UnresolvedNonce {
                nonce: 21,
                tx_hash: pending,
            } => assert_eq!(pending, tx_hash),
            other => panic!("{other}"),
        }
        requests.await.unwrap();
    }

    #[tokio::test]
    async fn stale_recovery_must_not_clear_a_different_transaction_with_the_same_nonce() {
        let (client, requests) = http_fixture(vec![
            Some(json!({"nonce": 21})),
            None,
            Some(json!({"nonce": 21})),
            None,
        ])
        .await;
        let Error::Unknown {
            nonce, tx_hash: a, ..
        } = client.place_order(&ORDER).await.unwrap_err()
        else {
            panic!("expected A to be unresolved")
        };
        assert!(client.resume_after_reconciliation(nonce, &a).await);
        let order_b = LimitOrder {
            client_order_index: 124,
            ..ORDER
        };
        let Error::Unknown {
            nonce: nonce_b,
            tx_hash: b,
            ..
        } = client.place_order(&order_b).await.unwrap_err()
        else {
            panic!("expected B to be unresolved")
        };
        assert_eq!(nonce, nonce_b);
        assert_ne!(a, b);
        requests.await.unwrap();
        assert!(
            !client.resume_after_reconciliation(nonce, &a).await,
            "A's delayed recovery cleared unresolved B despite different hashes"
        );
        assert!(client.resume_after_reconciliation(nonce, &b).await);
    }

    #[cfg(feature = "websocket")]
    #[tokio::test]
    async fn missing_ws_ack_replays_the_same_signed_transaction() {
        use futures_util::StreamExt;
        use tokio_tungstenite::tungstenite::Message;

        let (mut client, requests) = http_fixture(vec![
            Some(json!({"nonce": 21})),
            Some(json!({"code": 200, "tx_hash": "matching"})),
        ])
        .await;
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let (got_frame, frame) = tokio::sync::oneshot::channel();

        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(socket).await.unwrap();
            while let Some(Ok(message)) = socket.next().await {
                if let Message::Text(text) = message {
                    let value: Value = serde_json::from_str(&text).unwrap();
                    got_frame.send(value).unwrap();
                    return;
                }
            }
            panic!("no signed WebSocket payload");
        });
        client.ws = Some(crate::ws_send::WsSender::new(url));
        client.warm_websocket();
        tokio::time::timeout(Duration::from_secs(2), async {
            while !client.ws.as_ref().unwrap().is_connected() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        let receipt = client.place_order(&ORDER).await.unwrap();
        assert_eq!(receipt.route, Route::WebSocketThenRest);
        assert_eq!(receipt.tx_hash.len(), 80);
        let frame = frame.await.unwrap();
        let requests = requests.await.unwrap();
        assert_eq!(frame["type"], "jsonapi/sendtx");
        assert_eq!(frame["data"]["tx_type"], 14);
        assert_eq!(frame["data"]["tx_info"], requests[1].signed_payload());
        server.await.unwrap();
    }
}

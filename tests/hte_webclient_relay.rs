//! HTE: the in-browser client sets up its relay differently from a desktop
//! client. It sends only a `PunchHoleRequest` over the WebSocket rendezvous
//! (nat_type SYMMETRIC, force_relay), the target picks the relay uuid and
//! answers with a `RelayResponse` over TCP, and the browser joins hbbr with
//! that uuid. The `RequestRelay` hbbs admits on never passes through hbbs, so
//! only the target's `RelayResponse` can admit the session. Real hbbs and
//! hbbr, a fake console, a fake target and a fake browser.

use axum::{extract::Extension, http::{HeaderMap, StatusCode}, routing::{get, post}, Router};
use hbb_common::{
    bytes::Bytes,
    bytes_codec::BytesCodec,
    futures_util::{sink::SinkExt, stream::StreamExt},
    protobuf::Message as _,
    rendezvous_proto::*,
    tokio::{self, io::{AsyncReadExt, AsyncWriteExt}, net::{TcpStream, UdpSocket}, time::{sleep, timeout}},
    tokio_util::codec::Framed,
};
use sodiumoxide::crypto::{auth::hmacsha256, hash::sha256};
use std::{process::{Child, Command, Stdio}, sync::Arc, time::Duration};
use tokio_tungstenite::{connect_async, tungstenite::{client::IntoClientRequest, Message}};

const HBBS: i32 = 31306; // websocket on +2
const HBBR: i32 = 31316; // websocket on +2
const GATE: &str = "31326";
const SECRET: &str = "test-link-secret";
const KEY: &str = "webclient-test-key";

struct Proc(Child);
impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn ticket(user: &str) -> String {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let signed = format!("cdw1.{}.web-{user}", now + 600);
    let mut st = hmacsha256::State::init(SECRET.as_bytes());
    st.update(signed.as_bytes());
    let sig: String = st.finalize().0.iter().map(|b| format!("{b:02x}")).collect();
    format!("{signed}.{sig}")
}

#[allow(dead_code)]
fn sha256_hex(s: &str) -> String {
    sha256::hash(s.as_bytes()).0.iter().map(|b| format!("{b:02x}")).collect()
}

async fn policy(Extension(body): Extension<Arc<String>>, headers: HeaderMap) -> (StatusCode, String) {
    if headers.get("authorization").and_then(|v| v.to_str().ok()) != Some(&format!("Bearer {SECRET}")) {
        return (StatusCode::UNAUTHORIZED, String::new());
    }
    (StatusCode::OK, (*body).clone())
}

async fn ok() -> StatusCode {
    StatusCode::OK
}

fn start_console() -> String {
    let body = serde_json::json!({
        "mode": "approved", "allow": ["web-target", "web-elsewhere"], "incoming_only": [],
        "tokens": {}, "ip_match": false,
        "scope": { "enforce": true, "users": {
            "7": {"name": "mperez", "all": false, "devices": ["web-target"]},
            "9": {"name": "other", "all": false, "devices": ["web-elsewhere"]},
        }, "token_users": {} }
    })
    .to_string();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let app = Router::new()
        .route("/api/server/policy", get(policy))
        .route("/api/server/local-addrs", post(ok))
        .route("/api/server/refusals", post(ok))
        .layer(Extension(Arc::new(body)));
    tokio::spawn(async move {
        axum::Server::from_tcp(listener).unwrap().serve(app.into_make_service()).await.ok();
    });
    url
}

async fn admin(port: i32, cmd: &str) -> String {
    let Ok(mut s) = TcpStream::connect(format!("127.0.0.1:{}", port - 1)).await else { return String::new() };
    s.write_all(cmd.as_bytes()).await.ok();
    let mut out = String::new();
    timeout(Duration::from_secs(2), s.read_to_string(&mut out)).await.ok();
    out
}

async fn spawn(dir: &std::path::Path, console: &str) -> (Proc, Proc, String) {
    let hbbs = Command::new(env!("CARGO_BIN_EXE_hbbs"))
        .current_dir(dir)
        .args(["-p", &HBBS.to_string(), "-k", "_"])
        .env("TEST_HBBS", "no")
        .env("CORTENDESK_CONSOLE_URL", console)
        .env("CORTENDESK_SERVER_SECRET", SECRET)
        .env("CORTENDESK_POLICY_INTERVAL", "1")
        .env("HTE_RELAY_GATE_PORT", GATE)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("hbbs starts");
    let mut hbbs = hbbs;
    let stdout = hbbs.stdout.take().expect("stdout piped");
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        use std::io::BufRead;
        let mut tx = Some(tx);
        for line in std::io::BufReader::new(stdout).lines().map_while(Result::ok) {
            if let Some(k) = line.split("Key: ").nth(1) {
                if let Some(tx) = tx.take() {
                    tx.send(k.trim().to_owned()).ok();
                }
            }
        }
    });
    let key = rx.recv_timeout(Duration::from_secs(20)).expect("hbbs logs its key");
    let hbbr = Command::new(env!("CARGO_BIN_EXE_hbbr"))
        .current_dir(dir)
        .args(["-p", &HBBR.to_string(), "-k", KEY])
        .env("HTE_RELAY_GATE_PORT", GATE)
        .env_remove("KEY")
        .env_remove("PORT")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("hbbr starts");
    for _ in 0..100 {
        if TcpStream::connect(format!("127.0.0.1:{}", HBBR + 2)).await.is_ok()
            && TcpStream::connect(format!("127.0.0.1:{}", HBBS + 2)).await.is_ok()
            && admin(HBBS, "pol").await.contains("mode=approved")
        {
            return (Proc(hbbs), Proc(hbbr), key);
        }
        sleep(Duration::from_millis(100)).await;
    }
    panic!("hbbs/hbbr never came up");
}

type Ws = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>;

async fn ws_recv(ws: &mut Ws, ms: u64) -> Option<Vec<u8>> {
    loop {
        match timeout(Duration::from_millis(ms), ws.next()).await {
            Ok(Some(Ok(Message::Binary(b)))) => return Some(b.to_vec()),
            Ok(Some(Ok(_))) => continue,
            _ => return None,
        }
    }
}

async fn relay_join(uuid: &str) -> Ws {
    let (mut ws, _) = connect_async(format!("ws://127.0.0.1:{}", HBBR + 2)).await.expect("relay ws connects");
    let mut msg = RendezvousMessage::new();
    msg.set_request_relay(RequestRelay { uuid: uuid.to_owned(), licence_key: KEY.to_owned(), ..Default::default() });
    ws.send(Message::Binary(msg.write_to_bytes().unwrap().into())).await.unwrap();
    ws
}

async fn register(id: &str) -> UdpSocket {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut msg = RendezvousMessage::new();
    msg.set_register_pk(RegisterPk {
        id: id.to_owned(), uuid: format!("uuid-{id}").into_bytes().into(), pk: vec![7u8; 32].into(), ..Default::default()
    });
    let bytes = msg.write_to_bytes().unwrap();
    let mut buf = [0u8; 1024];
    for _ in 0..50 {
        sock.send_to(&bytes, format!("127.0.0.1:{HBBS}")).await.ok();
        if timeout(Duration::from_millis(200), sock.recv_from(&mut buf)).await.is_ok() {
            return sock;
        }
    }
    panic!("{id} never registered");
}

/// The browser: a WebSocket to hbbs behind a proxy that sets X-Forwarded-For
/// (hbbs then sees the client as `ip:0`), asking for a punch hole with relay.
async fn browser_punch(key: &str, target: &str, token: &str) -> Ws {
    let mut req = format!("ws://127.0.0.1:{}", HBBS + 2).into_client_request().unwrap();
    req.headers_mut().insert("X-Forwarded-For", "203.0.113.9".parse().unwrap());
    let (mut ws, _) = connect_async(req).await.expect("rendezvous ws connects");
    let mut msg = RendezvousMessage::new();
    msg.set_punch_hole_request(PunchHoleRequest {
        id: target.to_owned(),
        licence_key: key.to_owned(),
        token: token.to_owned(),
        nat_type: NatType::SYMMETRIC.into(),
        force_relay: true,
        ..Default::default()
    });
    ws.send(Message::Binary(msg.write_to_bytes().unwrap().into())).await.unwrap();
    ws
}

/// The target: gets the PunchHole over UDP, picks a uuid, goes to hbbr first
/// and tells hbbs over TCP, the way the desktop client's `create_relay` does.
async fn target_answers(udp: &UdpSocket, uuid: &str) -> Option<()> {
    let mut buf = [0u8; 2048];
    let (n, _) = timeout(Duration::from_secs(5), udp.recv_from(&mut buf)).await.ok()?.ok()?;
    let ph = match RendezvousMessage::parse_from_bytes(&buf[..n]).ok()?.union {
        Some(rendezvous_message::Union::PunchHole(ph)) => ph,
        _ => return None,
    };
    let s = TcpStream::connect(format!("127.0.0.1:{HBBS}")).await.ok()?;
    let mut conn = Framed::new(s, BytesCodec::new());
    let mut msg = RendezvousMessage::new();
    let mut rr = RelayResponse {
        socket_addr: ph.socket_addr,
        uuid: uuid.to_owned(),
        relay_server: format!("127.0.0.1:{HBBR}"),
        ..Default::default()
    };
    rr.set_id("web-target".to_owned());
    msg.set_relay_response(rr);
    conn.send(Bytes::from(msg.write_to_bytes().ok()?)).await.ok()?;
    std::mem::forget(conn); // the target keeps its signalling connection open
    Some(())
}

/// Browser asks, target answers, browser gets the uuid from hbbs and joins
/// the relay; true when bytes cross between the two.
async fn web_session(key: &str, udp: &UdpSocket, token: &str, uuid: &str) -> bool {
    let mut browser = browser_punch(key, "web-target", token).await;
    if target_answers(udp, uuid).await.is_none() {
       
        return false;
    }
    let target_side = relay_join(uuid).await; // the target reaches hbbr first
    let Some(bytes) = ws_recv(&mut browser, 5000).await else { return false };
    let got = match RendezvousMessage::parse_from_bytes(&bytes).unwrap().union {
        Some(rendezvous_message::Union::RelayResponse(rr)) => rr.uuid,
        o => { return false },
    };
    assert_eq!(got, uuid, "hbbs hands the browser the target's uuid");
    let mut browser_side = relay_join(&got).await;
    let mut target_side = target_side;
    sleep(Duration::from_millis(300)).await;
    browser_side.send(Message::Binary(b"hello".to_vec().into())).await.ok();
    let r = ws_recv(&mut target_side, 6000).await;
   
    r.as_deref() == Some(&b"hello"[..])
}

#[tokio::test]
async fn a_web_client_session_hbbs_admitted_pairs_and_others_do_not() {
    let url = start_console();
    let dir = tempfile::tempdir().unwrap();
    let (_hbbs, _hbbr, key) = spawn(dir.path(), &url).await;
    let udp = register("web-target").await;

    // Signed in, the computer is in reach: the session pairs.
    assert!(web_session(&key, &udp, &ticket("7"), "web-admitted").await, "an admitted web session pairs");

    // Out of reach: hbbs refuses the punch hole, the target is never asked,
    // and the uuid a target-less browser might invent does not pair either.
    for token in [ticket("9"), String::new()] {
        let mut browser = browser_punch(&key, "web-target", &token).await;
        let refused = ws_recv(&mut browser, 3000).await.map(|b| RendezvousMessage::parse_from_bytes(&b).unwrap());
        assert!(matches!(refused.and_then(|m| m.union), Some(rendezvous_message::Union::PunchHoleResponse(_))));
        let mut buf = [0u8; 64];
        assert!(timeout(Duration::from_millis(500), udp.recv_from(&mut buf)).await.is_err(), "no PunchHole for a refused person");
    }
    assert!(!unpaired("web-refused").await, "a uuid for a refused session must not pair");

    // A uuid nobody told hbbs about, with the public key: still refused.
    assert!(!unpaired("web-made-up").await, "a never-admitted uuid must not pair");

    // A RelayResponse that names a device hbbs does not know admits nothing.
    let s = TcpStream::connect(format!("127.0.0.1:{HBBS}")).await.unwrap();
    let mut conn = Framed::new(s, BytesCodec::new());
    let mut msg = RendezvousMessage::new();
    let mut rr = RelayResponse { uuid: "web-forged".into(), ..Default::default() };
    rr.set_id("web-nobody".to_owned());
    msg.set_relay_response(rr);
    conn.send(Bytes::from(msg.write_to_bytes().unwrap())).await.unwrap();
    sleep(Duration::from_millis(300)).await;
    assert!(!unpaired("web-forged").await, "a forged RelayResponse must not admit a uuid");
}

/// Two joiners present the same uuid and the public key; true if bytes cross.
async fn unpaired(uuid: &str) -> bool {
    let mut a = relay_join(uuid).await;
    sleep(Duration::from_millis(300)).await;
    let mut b = relay_join(uuid).await;
    sleep(Duration::from_millis(300)).await;
    a.send(Message::Binary(b"x".to_vec().into())).await.ok();
    ws_recv(&mut b, 4000).await.is_some()
}

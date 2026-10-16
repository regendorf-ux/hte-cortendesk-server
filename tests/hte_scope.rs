//! HTE (2026-10-16): per-person reach against a real hbbs and a fake console.
//! A person reaches the devices in their scope and nothing else; an
//! administrator reaches everything; the web client's ticket is scoped the
//! same way; nobody signed in is refused; refusals are reported to the
//! console once per retry burst; enforcement off is today's behaviour; a
//! console outage keeps the last scope. The helpers mirror access_policy.rs.

use axum::{
    extract::Extension,
    http::{HeaderMap, HeaderValue, StatusCode},
    routing::{get, post},
    Router,
};
use hbb_common::{
    bytes::Bytes,
    bytes_codec::BytesCodec,
    futures_util::{sink::SinkExt, stream::StreamExt},
    protobuf::Message as _,
    rendezvous_proto::*,
    tokio::{
        self,
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpStream, UdpSocket},
        time::{sleep, timeout},
    },
    tokio_util::codec::Framed,
};
use sodiumoxide::crypto::{auth::hmacsha256, hash::sha256};
use std::{
    io::{BufRead, BufReader},
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

// Clear of every other test file's ports (each hbbs takes port-1 and port+2).
const PORT_SCOPE: i32 = 31256;
const PORT_OPEN: i32 = 31266;

const SECRET: &str = "test-link-secret";
const DENY_SCOPE: &str = "You are not given access to this device";
const DENY_NOBODY: &str = "Only signed-in people may reach devices";
const DENY_UNAPPROVED: &str = "This device is not approved on this server";

#[derive(Default)]
struct Console {
    body: String,
    version: u32,
    fail: bool,
    refusals: Vec<serde_json::Value>,
}
type Shared = Arc<Mutex<Console>>;

fn authorized(headers: &HeaderMap) -> bool {
    headers.get("authorization").and_then(|v| v.to_str().ok()) == Some(&format!("Bearer {SECRET}"))
}

async fn policy(Extension(st): Extension<Shared>, headers: HeaderMap) -> (StatusCode, HeaderMap, String) {
    let c = st.lock().unwrap();
    let mut out = HeaderMap::new();
    if !authorized(&headers) {
        return (StatusCode::UNAUTHORIZED, out, String::new());
    }
    if c.fail {
        return (StatusCode::INTERNAL_SERVER_ERROR, out, String::new());
    }
    let etag = format!("\"v{}\"", c.version);
    out.insert("etag", HeaderValue::from_str(&etag).unwrap());
    if headers.get("if-none-match").and_then(|v| v.to_str().ok()) == Some(etag.as_str()) {
        return (StatusCode::NOT_MODIFIED, out, String::new());
    }
    (StatusCode::OK, out, c.body.clone())
}

async fn refusals(Extension(st): Extension<Shared>, headers: HeaderMap, body: String) -> StatusCode {
    if !authorized(&headers) {
        return StatusCode::UNAUTHORIZED;
    }
    let mut c = st.lock().unwrap();
    if c.fail {
        return StatusCode::INTERNAL_SERVER_ERROR;
    }
    let v: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
    if let Some(items) = v.get("refusals").and_then(|r| r.as_array()) {
        c.refusals.extend(items.iter().cloned());
    }
    StatusCode::OK
}

async fn ignore_addrs() -> StatusCode {
    StatusCode::OK
}

fn set_policy(st: &Shared, body: serde_json::Value) {
    let mut c = st.lock().unwrap();
    c.body = body.to_string();
    c.version += 1;
}

fn start_console(body: serde_json::Value) -> (String, Shared) {
    let st: Shared = Default::default();
    set_policy(&st, body);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let app = Router::new()
        .route("/api/server/policy", get(policy))
        .route("/api/server/refusals", post(refusals))
        .route("/api/server/local-addrs", post(ignore_addrs))
        .layer(Extension(st.clone()));
    tokio::spawn(async move {
        axum::Server::from_tcp(listener).unwrap().serve(app.into_make_service()).await.ok();
    });
    (url, st)
}

struct Hbbs(Child);
impl Drop for Hbbs {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn_hbbs(dir: &std::path::Path, port: i32, console: &str) -> (Hbbs, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_hbbs"));
    cmd.current_dir(dir)
        .args(["-p", &port.to_string(), "-k", "_"])
        .env("TEST_HBBS", "no")
        .env("CORTENDESK_CONSOLE_URL", console)
        .env("CORTENDESK_SERVER_SECRET", SECRET)
        .env("CORTENDESK_POLICY_INTERVAL", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = cmd.spawn().expect("hbbs starts");
    let stdout = child.stdout.take().expect("stdout piped");
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut tx = Some(tx);
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if let Some(k) = line.split("Key: ").nth(1) {
                if let Some(tx) = tx.take() {
                    tx.send(k.trim().to_owned()).ok();
                }
            }
        }
    });
    let key = rx.recv_timeout(Duration::from_secs(20)).expect("hbbs logs its key");
    (Hbbs(child), key)
}

async fn admin(port: i32, cmd: &str) -> String {
    let Ok(mut s) = TcpStream::connect(format!("127.0.0.1:{}", port - 1)).await else {
        return String::new();
    };
    s.write_all(cmd.as_bytes()).await.ok();
    let mut out = String::new();
    timeout(Duration::from_secs(2), s.read_to_string(&mut out)).await.ok();
    out
}

async fn wait_policy(port: i32, needle: &str) {
    let mut last = String::new();
    for _ in 0..100 {
        last = admin(port, "pol").await;
        if last.contains(needle) {
            return;
        }
        sleep(Duration::from_millis(100)).await;
    }
    panic!("policy never showed {needle:?}, last: {last:?}");
}

struct Peer {
    sock: UdpSocket,
    id: String,
}

impl Peer {
    async fn register(port: i32, id: &str) -> Peer {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut msg = RendezvousMessage::new();
        msg.set_register_pk(RegisterPk {
            id: id.to_owned(),
            uuid: format!("uuid-{id}").into_bytes().into(),
            pk: vec![7u8; 32].into(),
            ..Default::default()
        });
        let bytes = msg.write_to_bytes().unwrap();
        let mut buf = [0u8; 1024];
        for _ in 0..50 {
            sock.send_to(&bytes, format!("127.0.0.1:{port}")).await.ok();
            if let Ok(Ok((n, _))) = timeout(Duration::from_millis(200), sock.recv_from(&mut buf)).await {
                let res = RendezvousMessage::parse_from_bytes(&buf[..n]).unwrap();
                match res.union {
                    Some(rendezvous_message::Union::RegisterPkResponse(r)) => {
                        assert_eq!(r.result.enum_value(), Ok(register_pk_response::Result::OK), "{id} registers");
                        return Peer { sock, id: id.to_owned() };
                    }
                    other => panic!("unexpected reply to RegisterPk: {other:?}"),
                }
            }
        }
        panic!("hbbs never answered RegisterPk for {id}");
    }

    async fn forwarded(&self, ms: u64) -> Option<RendezvousMessage> {
        let mut buf = [0u8; 1024];
        let deadline = hbb_common::tokio::time::Instant::now() + Duration::from_millis(ms);
        loop {
            let left = deadline.saturating_duration_since(hbb_common::tokio::time::Instant::now());
            let (n, _) = timeout(left, self.sock.recv_from(&mut buf)).await.ok()?.ok()?;
            let msg = RendezvousMessage::parse_from_bytes(&buf[..n]).ok()?;
            if !matches!(msg.union, Some(rendezvous_message::Union::RegisterPkResponse(_))) {
                return Some(msg);
            }
        }
    }
}

type Conn = Framed<TcpStream, BytesCodec>;

async fn connect(port: i32) -> Conn {
    for _ in 0..100 {
        if let Ok(s) = TcpStream::connect(format!("127.0.0.1:{port}")).await {
            return Framed::new(s, BytesCodec::new());
        }
        sleep(Duration::from_millis(100)).await;
    }
    panic!("hbbs never accepted a connection on {port}");
}

async fn send(conn: &mut Conn, msg: RendezvousMessage) {
    conn.send(Bytes::from(msg.write_to_bytes().unwrap())).await.expect("request sent");
}

async fn reply(conn: &mut Conn, ms: u64) -> Option<RendezvousMessage> {
    loop {
        let bytes = match timeout(Duration::from_millis(ms), conn.next()).await {
            Ok(Some(Ok(b))) => b,
            _ => return None,
        };
        let msg = RendezvousMessage::parse_from_bytes(&bytes).expect("reply parses");
        if !matches!(msg.union, Some(rendezvous_message::Union::KeyExchange(_))) {
            return Some(msg);
        }
    }
}

async fn punch(port: i32, key: &str, target: &str, token: &str) -> Conn {
    let mut conn = connect(port).await;
    let mut msg = RendezvousMessage::new();
    msg.set_punch_hole_request(PunchHoleRequest {
        id: target.to_owned(),
        token: token.to_owned(),
        licence_key: key.to_owned(),
        version: "1.5.0".to_owned(),
        ..Default::default()
    });
    send(&mut conn, msg).await;
    conn
}

async fn request_relay(port: i32, target: &str, token: &str) -> Conn {
    let mut conn = connect(port).await;
    let mut msg = RendezvousMessage::new();
    msg.set_request_relay(RequestRelay {
        id: target.to_owned(),
        uuid: "5c8a1d9e-relay-test".to_owned(),
        token: token.to_owned(),
        ..Default::default()
    });
    send(&mut conn, msg).await;
    conn
}

async fn assert_refused(conn: &mut Conn, text: &str) {
    match reply(conn, 3000).await.map(|m| m.union) {
        Some(Some(rendezvous_message::Union::PunchHoleResponse(ph))) => {
            assert!(ph.socket_addr.is_empty(), "a refusal carries no address");
            assert!(ph.other_failure.contains(text), "expected {text:?}, got {:?}", ph.other_failure);
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

async fn assert_relay_refused(conn: &mut Conn, text: &str) {
    match reply(conn, 3000).await.map(|m| m.union) {
        Some(Some(rendezvous_message::Union::RelayResponse(rr))) => {
            assert!(rr.refuse_reason.contains(text), "expected {text:?}, got {:?}", rr.refuse_reason)
        }
        other => panic!("expected a relay refusal, got {other:?}"),
    }
}

async fn assert_forwarded(conn: &mut Conn, target: &Peer) {
    let msg = target.forwarded(3000).await;
    match msg.map(|m| m.union) {
        Some(Some(rendezvous_message::Union::FetchLocalAddr(_))) => {}
        other => panic!("{} should have been asked for its local address, got {other:?}", target.id),
    }
    assert!(reply(conn, 300).await.is_none(), "the initiator must not be refused");
}

fn sha256_hex(s: &str) -> String {
    sha256::hash(s.as_bytes()).0.iter().map(|b| format!("{b:02x}")).collect()
}

fn ticket(user: &str) -> String {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let signed = format!("cdw1.{}.web-{user}", now + 600);
    let mut st = hmacsha256::State::init(SECRET.as_bytes());
    st.update(signed.as_bytes());
    let sig: String = st.finalize().0.iter().map(|b| format!("{b:02x}")).collect();
    format!("{signed}.{sig}")
}

/// HTE's set-up: approved devices only, nobody found by IP, two people.
fn hte_policy(enforce: bool) -> serde_json::Value {
    serde_json::json!({
        "mode": "approved",
        "allow": ["sc-maria", "sc-osvaldo", "sc-front", "sc-server"],
        "incoming_only": [],
        "tokens": {
            sha256_hex("token-maria"): "sc-maria",
            sha256_hex("token-osvaldo"): "sc-osvaldo",
        },
        "ip_match": false,
        "scope": {
            "enforce": enforce,
            "users": {
                "7": {"name": "mperez", "all": false, "devices": ["sc-front"]},
                "8": {"name": "oduran", "all": true, "devices": []},
            },
            "token_users": {
                sha256_hex("token-maria"): "7",
                sha256_hex("token-osvaldo"): "8",
            }
        }
    })
}

#[tokio::test]
async fn a_person_reaches_only_their_scope() {
    let (url, console) = start_console(hte_policy(true));
    let dir = tempfile::tempdir().unwrap();
    let (_hbbs, key) = spawn_hbbs(dir.path(), PORT_SCOPE, &url);
    wait_policy(PORT_SCOPE, "scope=on people=2").await;

    let front = Peer::register(PORT_SCOPE, "sc-front").await;
    let server = Peer::register(PORT_SCOPE, "sc-server").await;
    let _maria = Peer::register(PORT_SCOPE, "sc-maria").await;

    // María reaches the front desk, not the server; by punch and by relay.
    let mut conn = punch(PORT_SCOPE, &key, &front.id, "token-maria").await;
    assert_forwarded(&mut conn, &front).await;
    let mut conn = punch(PORT_SCOPE, &key, &server.id, "token-maria").await;
    assert_refused(&mut conn, DENY_SCOPE).await;
    let mut conn = request_relay(PORT_SCOPE, &server.id, "token-maria").await;
    assert_relay_refused(&mut conn, DENY_SCOPE).await;
    assert!(server.forwarded(300).await.is_none(), "nothing reaches the server");

    // The administrator reaches everything.
    let mut conn = punch(PORT_SCOPE, &key, &server.id, "token-osvaldo").await;
    assert_forwarded(&mut conn, &server).await;

    // The console's web client is scoped the same way.
    let mut conn = punch(PORT_SCOPE, &key, &server.id, &ticket("7")).await;
    assert_refused(&mut conn, DENY_SCOPE).await;
    let mut conn = punch(PORT_SCOPE, &key, &server.id, &ticket("8")).await;
    assert_forwarded(&mut conn, &server).await;

    // Not signed in: refused as before (approved mode, no IP match).
    let mut conn = punch(PORT_SCOPE, &key, &front.id, "").await;
    assert_refused(&mut conn, DENY_UNAPPROVED).await;

    // María's two attempts on the server from her device were one burst: one
    // report, naming her; her web-client attempt is a second origin.
    sleep(Duration::from_millis(2500)).await;
    let reports = console.lock().unwrap().refusals.clone();
    let mine: Vec<_> = reports.iter().filter(|r| r["to"] == "sc-server" && r["from"] == "sc-maria").collect();
    assert_eq!(mine.len(), 1, "one refusal per person, origin and target per minute, got {reports:?}");
    assert_eq!(reports.iter().filter(|r| r["to"] == "sc-server" && r["from"] == "web").count(), 1);
    assert_eq!(mine[0]["user_id"], "7");
    assert_eq!(mine[0]["user_name"], "mperez");
    assert_eq!(mine[0]["from"], "sc-maria");
    assert_eq!(mine[0]["reason"], "outside scope");
    assert_eq!(mine[0]["ip"], "127.0.0.1");

    // The console goes down: the last scope still holds.
    console.lock().unwrap().fail = true;
    sleep(Duration::from_millis(1500)).await;
    let mut conn = punch(PORT_SCOPE, &key, &front.id, "token-maria").await;
    assert_forwarded(&mut conn, &front).await;
    let mut conn = punch(PORT_SCOPE, &key, &server.id, &ticket("7")).await;
    assert_refused(&mut conn, DENY_SCOPE).await;

    // Enforcement off: today's behaviour, any approved signed-in client.
    {
        let mut c = console.lock().unwrap();
        c.fail = false;
    }
    set_policy(&console, hte_policy(false));
    wait_policy(PORT_SCOPE, "scope=off").await;
    let mut conn = punch(PORT_SCOPE, &key, &server.id, "token-maria").await;
    assert_forwarded(&mut conn, &server).await;
}

/// Open mode with enforcement on: a device found only by its IP has no
/// person behind it and is refused; a signed-in person still passes.
#[tokio::test]
async fn nobody_signed_in_is_refused_when_enforcing() {
    let mut body = hte_policy(true);
    body["mode"] = "open".into();
    let (url, _console) = start_console(body);
    let dir = tempfile::tempdir().unwrap();
    let (_hbbs, key) = spawn_hbbs(dir.path(), PORT_OPEN, &url);
    wait_policy(PORT_OPEN, "mode=open").await;

    let front = Peer::register(PORT_OPEN, "sc-front").await;
    let _stranger = Peer::register(PORT_OPEN, "sc-stranger").await;

    let mut conn = punch(PORT_OPEN, &key, &front.id, "").await;
    assert_refused(&mut conn, DENY_NOBODY).await;
    let mut conn = punch(PORT_OPEN, &key, &front.id, "token-maria").await;
    assert_forwarded(&mut conn, &front).await;
}

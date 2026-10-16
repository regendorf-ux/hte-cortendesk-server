//! HTE (2026-10-16): ask a live hbbs whether a session may start, the way a
//! client does, and print the answer. For proving per-person reach against
//! the real server without touching anyone's installed client.
//!
//!   cargo run --example hte_probe -- <host:port> <key> <target id> [token] [relay uuid]
//!
//! `token` is a console access token (what a signed-in client sends) or a
//! console web-client ticket. Prints REFUSED <reason>, ADMITTED (hbbs
//! answered with a punch-hole response or asked the target, no refusal) or
//! the raw reply.

use hbb_common::{
    bytes::Bytes,
    bytes_codec::BytesCodec,
    futures_util::{sink::SinkExt, stream::StreamExt},
    protobuf::Message as _,
    rendezvous_proto::*,
    tokio::{self, net::TcpStream, time::timeout},
    tokio_util::codec::Framed,
};
use std::time::Duration;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        eprintln!("usage: hte_probe <host:port> <key> <target id> [token]");
        std::process::exit(2);
    }
    let token = args.get(4).cloned().unwrap_or_default();
    let stream = TcpStream::connect(&args[1]).await.expect("connect");
    let mut conn = Framed::new(stream, BytesCodec::new());
    let mut msg = RendezvousMessage::new();
    // A fifth argument asks for a relay with that uuid instead of a punch hole.
    if let Some(uuid) = args.get(5) {
        msg.set_request_relay(RequestRelay {
            id: args[3].clone(),
            uuid: uuid.clone(),
            token,
            licence_key: args[2].clone(),
            ..Default::default()
        });
    } else {
        msg.set_punch_hole_request(PunchHoleRequest {
            id: args[3].clone(),
            token,
            licence_key: args[2].clone(),
            version: "1.5.0".to_owned(),
            ..Default::default()
        });
    }
    conn.send(Bytes::from(msg.write_to_bytes().unwrap())).await.expect("send");
    let deadline = Duration::from_secs(6);
    loop {
        let bytes = match timeout(deadline, conn.next()).await {
            Ok(Some(Ok(b))) => b,
            Ok(Some(Err(e))) => { println!("ERROR {e}"); return; }
            Ok(None) => { println!("CLOSED"); return; }
            Err(_) => { println!("ADMITTED (no refusal within {deadline:?})"); return; }
        };
        let reply = RendezvousMessage::parse_from_bytes(&bytes).expect("parse");
        match reply.union {
            Some(rendezvous_message::Union::KeyExchange(_)) => continue,
            Some(rendezvous_message::Union::PunchHoleResponse(ph)) => {
                if !ph.other_failure.is_empty() {
                    println!("REFUSED {}", ph.other_failure);
                } else {
                    println!("PUNCH_HOLE_RESPONSE failure={:?} addr_len={}", ph.failure, ph.socket_addr.len());
                }
                return;
            }
            Some(rendezvous_message::Union::RelayResponse(rr)) => {
                println!("RELAY_RESPONSE refuse_reason={:?}", rr.refuse_reason);
                return;
            }
            other => { println!("REPLY {other:?}"); return; }
        }
    }
}

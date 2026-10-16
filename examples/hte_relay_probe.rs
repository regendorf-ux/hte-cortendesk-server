//! HTE (2026-10-16): does a live hbbr pair two connections with this uuid?
//!
//!   cargo run --example hte_relay_probe -- <host:port> <key> <uuid> [one]
//!
//! Opens two TCP connections to the relay with the same uuid (or, with
//! `one`, a single connection, as the second side of a session whose first
//! side is already waiting) and reports PAIRED when bytes cross, else
//! NOT PAIRED.

use hbb_common::{
    bytes::Bytes,
    bytes_codec::BytesCodec,
    futures_util::{sink::SinkExt, stream::StreamExt},
    protobuf::Message as _,
    rendezvous_proto::*,
    tokio::{self, net::TcpStream, time::{sleep, timeout}},
    tokio_util::codec::Framed,
};
use std::time::Duration;

async fn join(host: &str, key: &str, uuid: &str) -> Framed<TcpStream, BytesCodec> {
    let s = TcpStream::connect(host).await.expect("connect");
    let mut f = Framed::new(s, BytesCodec::new());
    let mut msg = RendezvousMessage::new();
    msg.set_request_relay(RequestRelay { uuid: uuid.to_owned(), licence_key: key.to_owned(), ..Default::default() });
    f.send(Bytes::from(msg.write_to_bytes().unwrap())).await.expect("send");
    f
}

#[tokio::main]
async fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 4 {
        eprintln!("usage: hte_relay_probe <host:port> <key> <uuid> [one]");
        std::process::exit(2);
    }
    if a.get(4).map(String::as_str) == Some("one") {
        let mut b = join(&a[1], &a[2], &a[3]).await;
        match timeout(Duration::from_secs(8), b.next()).await {
            Ok(Some(Ok(bytes))) => println!("PAIRED (the other side sent {} bytes)", bytes.len()),
            Ok(_) => println!("NOT PAIRED (closed)"),
            Err(_) => println!("NOT PAIRED or silent (nothing within 8 s)"),
        }
        return;
    }
    let mut x = join(&a[1], &a[2], &a[3]).await;
    sleep(Duration::from_millis(500)).await;
    let mut y = join(&a[1], &a[2], &a[3]).await;
    sleep(Duration::from_millis(4000)).await; // past the gate's grace
    x.send(Bytes::from_static(b"hte-relay-probe")).await.ok();
    match timeout(Duration::from_secs(4), y.next()).await {
        Ok(Some(Ok(b))) if &b[..] == b"hte-relay-probe" => println!("PAIRED"),
        _ => println!("NOT PAIRED"),
    }
}

// Added by HTE on 2026-10-16 for HTE Remote. See HTE.md.
// This file is part of a modified version of cortendesk-server, distributed
// under the AGPL-3.0 like the original.

//! The relay pairs only sessions the ID server let through.
//!
//! Upstream hbbr pairs any two connections that present the same uuid and the
//! server key, and the key is public (every client carries it). With this
//! gate on, hbbs tells hbbr each uuid it handed out for a session it admitted,
//! over a datagram on the loopback interface, and hbbr pairs a uuid only when
//! hbbs named it in the last two minutes. hbbs names a uuid at the two places
//! a relay is set up through it: a `RequestRelay` from the initiator, after the
//! policy (and per-person reach) let it through, and a `RelayResponse` from a
//! registered, approved target answering a punch hole.
//!
//! Off unless `HTE_RELAY_GATE_PORT` is set on both servers (the HTE console
//! image sets it). hbbs and hbbr must then run on the same host, as they do in
//! the CortenDesk image.

use hbb_common::{log, tokio};
use std::{
    collections::HashMap,
    net::{SocketAddr, UdpSocket},
    sync::Mutex,
    time::{Duration, Instant},
};

const PREFIX: &str = "hte1 ";
/// How long a named uuid may wait for its pair. Covers the 30 s a relay
/// waits for the second side, with room for a slow client.
const KEEP: Duration = Duration::from_secs(120);
/// How long the second side may wait at the relay for hbbs's word: the target
/// can reach hbbr a moment before its RelayResponse passes through hbbs.
const GRACE: Duration = Duration::from_secs(3);
const MAX_KEPT: usize = 20_000;

fn port() -> Option<u16> {
    std::env::var("HTE_RELAY_GATE_PORT")
        .ok()
        .and_then(|p| p.trim().parse::<u16>().ok())
        .filter(|p| *p > 0)
}

pub fn enabled() -> bool {
    port().is_some()
}

// ---- hbbs side ----------------------------------------------------------------

lazy_static::lazy_static! {
    static ref SENDER: Option<(UdpSocket, SocketAddr)> = port().and_then(|p| {
        let sock = UdpSocket::bind("127.0.0.1:0").ok()?;
        sock.set_nonblocking(true).ok()?;
        log::info!("Relay gate: telling hbbr about admitted sessions on 127.0.0.1:{p}");
        Some((sock, SocketAddr::from(([127, 0, 0, 1], p))))
    });
}

/// hbbs: a session with this relay uuid was admitted.
pub fn admit(uuid: &str) {
    if uuid.is_empty() || uuid.len() > 128 {
        return;
    }
    if let Some((sock, to)) = SENDER.as_ref() {
        if let Err(err) = sock.send_to(format!("{PREFIX}{uuid}").as_bytes(), to) {
            log::warn!("Relay gate: could not tell hbbr about {uuid}: {err}");
        }
    }
}

// ---- hbbr side ----------------------------------------------------------------

lazy_static::lazy_static! {
    static ref ADMITTED: Mutex<HashMap<String, Instant>> = Default::default();
}

fn note(uuid: &str) {
    let Ok(mut m) = ADMITTED.lock() else { return };
    if m.len() >= MAX_KEPT {
        m.retain(|_, t| t.elapsed() < KEEP);
    }
    if m.len() < MAX_KEPT {
        m.insert(uuid.to_owned(), Instant::now());
    }
}

fn known(uuid: &str) -> bool {
    ADMITTED
        .lock()
        .ok()
        .and_then(|m| m.get(uuid).map(|t| t.elapsed() < KEEP))
        .unwrap_or(false)
}

/// hbbr: listen for hbbs's word. Call from inside the runtime.
pub fn start_listener() {
    let Some(p) = port() else {
        log::info!("Relay gate off: set HTE_RELAY_GATE_PORT on hbbs and hbbr to pair only admitted sessions");
        return;
    };
    tokio::spawn(async move {
        let sock = match tokio::net::UdpSocket::bind(("127.0.0.1", p)).await {
            Ok(s) => s,
            Err(err) => {
                // Loud: with the gate on and no listener every relay is refused.
                log::error!("Relay gate: cannot listen on 127.0.0.1:{p}: {err}");
                return;
            }
        };
        log::info!("Relay gate on: pairing only sessions hbbs admitted (127.0.0.1:{p})");
        let mut buf = [0u8; 256];
        loop {
            let Ok((n, from)) = sock.recv_from(&mut buf).await else { continue };
            if !from.ip().is_loopback() {
                continue;
            }
            if let Some(uuid) = std::str::from_utf8(&buf[..n]).ok().and_then(|s| s.strip_prefix(PREFIX)) {
                note(uuid.trim());
            }
        }
    });
}

/// hbbr: may this uuid be paired? Waits up to GRACE for hbbs's word.
pub async fn admitted(uuid: &str) -> bool {
    if !enabled() {
        return true;
    }
    let start = Instant::now();
    loop {
        if known(uuid) {
            return true;
        }
        if start.elapsed() >= GRACE {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_noted_uuid_is_known_and_others_are_not() {
        note("unit-uuid-1");
        assert!(known("unit-uuid-1"));
        assert!(!known("unit-uuid-2"));
    }
}

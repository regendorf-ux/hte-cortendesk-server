//! PHP's `FtpTarget`: plain FTP or explicit FTPS (AUTH TLS) in passive mode, or active mode when the server refuses
//! passive. SFTP and implicit FTPS (port 990) are not supported, and the server's certificate is not verified (the
//! TLS handshake's signatures are, the chain is not), exactly as with PHP's ftp extension.
//!
//! Every public method uses its own connection with at most one transfer after a listing: ProFTPD, which requires
//! data connections to resume the control connection's TLS session, refuses a second one after an upload. The data
//! connections share the control connection's rustls config (and so its session cache) for that reason.

use crate::backup::is_backup_name;
use crate::backup_remote::Remote;
use std::cell::Cell;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme, StreamOwned};

const TIMEOUT: u64 = 15;
/// How long the server may take to confirm an upload.
const UPLOAD_TIMEOUT: u64 = 120;
/// What a passive data connection that never opened is reported as.
const NO_DATA_CONNECTION: &str = "the data connection did not open. Check that the server's passive port range is open in its firewall";

pub struct Ftp {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub path: String,
    pub tls: bool,
}

impl Remote for Ftp {
    /// Lists first. That proves the data connection before any of the archive goes out: if the client and the
    /// server disagree about encrypting it, the listing fails and nothing is sent in clear.
    fn put(&self, local: &Path, name: &str) -> Result<(), String> {
        let c = Client::new(self);
        let mut conn = c.connect()?;
        let r = c.put_on(&mut conn, local, name);
        conn.close();
        r
    }

    /// Sizes are asked for files named like backups only; None where the server will not say.
    fn list(&self) -> Result<Vec<(String, Option<u64>)>, String> {
        let c = Client::new(self);
        let mut conn = c.connect()?;
        let r = (|| {
            let mut files = vec![];
            for name in c.names(&mut conn)? {
                let size = if is_backup_name(&name) { conn.size_of(&name) } else { None };
                files.push((name, size));
            }
            Ok(files)
        })();
        conn.close();
        r
    }

    fn delete(&self, name: &str) -> Result<(), String> {
        let c = Client::new(self);
        let mut conn = c.connect()?;
        let r = match conn.delete(name) {
            Ok(()) => Ok(()),
            Err(d) => Err(failure(&format!("FTP delete of {name} failed"), &d, "")),
        };
        conn.close();
        r
    }

    /// List, upload a small file and delete it again: what a backup run does. A login alone proves nothing about the
    /// data connection, which is where passive mode and TLS go wrong.
    fn test(&self) -> Result<String, String> {
        let c = Client::new(self);
        let mut conn = c.connect()?;
        let r = c.test_on(&mut conn);
        conn.close();
        r
    }

    fn label(&self) -> String {
        Client::new(self).label()
    }
}

// ------------------------------------------------------------------------------------------------ small helpers ---

fn tidy(d: &str) -> String {
    d.trim().trim_end_matches(|c| c == '.' || c == ' ').to_string()
}

/// `RuntimeException`'s text: what happened, the server's own words, a hint for what they do not say.
fn failure(what: &str, detail: &str, hint: &str) -> String {
    let d = tidy(detail);
    format!("{what}{}.{}", if d.is_empty() { String::new() } else { format!(": {d}") }, if hint.is_empty() { String::new() } else { format!(" {}.", hint.trim_end_matches('.')) })
}

/// `FILTER_FLAG_GLOBAL_RANGE` for IPv4: not private, loopback, link-local, shared (CGNAT), documentation, benchmark,
/// reserved, multicast, broadcast or unspecified.
fn is_global_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    !(ip.is_unspecified()
        || ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_documentation()
        || (o[0] == 100 && (o[1] & 0xc0) == 64)
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)
        || (o[0] == 198 && (o[1] & 0xfe) == 18)
        || o[0] >= 240
        || o[0] == 0)
}

/// Whether data connections should go to the address in the server's PASV reply rather than to the host entered: only
/// when both are public and differ. A server behind NAT or in a container advertises a private address, and a NAS on
/// the LAN may advertise its WAN address; both are reached through the host entered.
pub fn use_pasv_address(advertised: &str, host: &str) -> bool {
    let public = |s: &str| s.parse::<Ipv4Addr>().map(is_global_v4).unwrap_or(false);
    advertised != host && public(advertised) && public(host)
}

fn timeoutish(e: &std::io::Error) -> bool {
    matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut)
}

fn io_text(e: &std::io::Error) -> String {
    if timeoutish(e) {
        return "timed out".into();
    }
    let s = e.to_string();
    // "Connection refused (os error 111)" -> "Connection refused"
    match s.find(" (os error") {
        Some(i) => s[..i].to_string(),
        None => s,
    }
}

// ------------------------------------------------------------------------------------------------------- TLS ---

#[derive(Debug)]
struct NoVerify(Arc<CryptoProvider>);

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(&self, _: &CertificateDer<'_>, _: &[CertificateDer<'_>], _: &ServerName<'_>, _: &[u8], _: UnixTime) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }
    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn tls_config() -> Result<Arc<ClientConfig>, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS12, &rustls::version::TLS13])
        .map_err(|e| format!("TLS is not available: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify(provider)))
        .with_no_client_auth();
    Ok(Arc::new(cfg))
}

// ---------------------------------------------------------------------------------------------------- streams ---

enum Stream {
    Plain(TcpStream),
    Tls(Box<StreamOwned<ClientConnection, TcpStream>>),
    Gone,
}

impl Stream {
    fn raw(&self) -> Option<&TcpStream> {
        match self {
            Stream::Plain(s) => Some(s),
            Stream::Tls(s) => Some(&s.sock),
            Stream::Gone => None,
        }
    }
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Stream::Plain(s) => s.read(buf),
            Stream::Tls(s) => s.read(buf),
            Stream::Gone => Ok(0),
        }
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Stream::Plain(s) => s.write(buf),
            Stream::Tls(s) => s.write(buf),
            Stream::Gone => Err(std::io::ErrorKind::NotConnected.into()),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Stream::Plain(s) => s.flush(),
            Stream::Tls(s) => s.flush(),
            Stream::Gone => Ok(()),
        }
    }
}

struct Reply {
    code: u32,
    lines: Vec<String>,
}

impl Reply {
    fn last(&self) -> &str {
        self.lines.last().map(String::as_str).unwrap_or("")
    }
    /// The server's words without the code, as PHP's warnings carry them.
    fn text(&self) -> String {
        let l = self.last();
        if l.len() > 4 && l.as_bytes()[..3].iter().all(u8::is_ascii_digit) {
            l[4..].trim().to_string()
        } else {
            l.trim().to_string()
        }
    }
    fn ok(&self) -> bool {
        (200..300).contains(&self.code)
    }
}

struct Control {
    r: BufReader<Stream>,
    cfg: Option<Arc<ClientConfig>>,
    name: ServerName<'static>,
    peer: SocketAddr,
    local: SocketAddr,
}

impl Control {
    fn set_timeout(&self, secs: u64) {
        if let Some(s) = self.r.get_ref().raw() {
            let _ = s.set_read_timeout(Some(Duration::from_secs(secs)));
            let _ = s.set_write_timeout(Some(Duration::from_secs(secs)));
        }
    }

    fn send(&mut self, line: &str) -> Result<(), String> {
        let w = self.r.get_mut();
        w.write_all(format!("{line}\r\n").as_bytes()).and_then(|_| w.flush()).map_err(|e| io_text(&e))
    }

    fn reply(&mut self) -> Result<Reply, String> {
        let mut lines: Vec<String> = vec![];
        let mut code = 0u32;
        loop {
            let mut l = String::new();
            match self.r.read_line(&mut l) {
                Ok(0) => return Err("connection closed by the server".into()),
                Ok(_) => {}
                Err(e) => return Err(io_text(&e)),
            }
            let l = l.trim_end_matches(['\r', '\n']).to_string();
            let b = l.as_bytes();
            let numeric = b.len() >= 3 && b[..3].iter().all(u8::is_ascii_digit);
            if lines.is_empty() {
                if !numeric {
                    // not an FTP reply at all
                    lines.push(l);
                    return Ok(Reply { code: 0, lines });
                }
                code = l[..3].parse().unwrap_or(0);
                let multi = b.len() > 3 && b[3] == b'-';
                lines.push(l);
                if !multi {
                    return Ok(Reply { code, lines });
                }
            } else {
                let end = numeric && l[..3].parse::<u32>().ok() == Some(code) && (b.len() == 3 || b[3] == b' ');
                lines.push(l);
                if end {
                    return Ok(Reply { code, lines });
                }
            }
        }
    }

    fn cmd(&mut self, line: &str) -> Result<Reply, String> {
        self.send(line)?;
        self.reply()
    }

    /// AUTH TLS, then the handshake over the same socket.
    fn upgrade(&mut self) -> Result<(), String> {
        let cfg = self.cfg.clone().ok_or("TLS is not available")?;
        let old = std::mem::replace(self.r.get_mut(), Stream::Gone);
        let Stream::Plain(sock) = old else { return Err("already encrypted".into()) };
        let conn = ClientConnection::new(cfg, self.name.clone()).map_err(|e| format!("handshake failed: {e}"))?;
        let mut tls = Box::new(StreamOwned::new(conn, sock));
        // drive the handshake now, so a failure surfaces here and not in a later command
        while tls.conn.is_handshaking() {
            tls.conn.complete_io(&mut tls.sock).map_err(|e| if timeoutish(&e) { "timed out".to_string() } else { format!("handshake failed: {}", io_text(&e)) })?;
        }
        *self.r.get_mut() = Stream::Tls(tls);
        Ok(())
    }
}

enum Xfer {
    /// the server answered the command with an error reply
    Refused(Reply),
    /// anything else; the text is what PHP's warning would have said
    Fail(String),
}

struct Conn {
    ctl: Option<Control>,
    cfg: Option<Arc<ClientConfig>>,
    active: bool,
    using_pasv_address: bool,
    advertised: Option<String>,
    host_address: String,
}

impl Conn {
    fn ctl(&mut self) -> Result<&mut Control, String> {
        self.ctl.as_mut().ok_or_else(|| "connection closed".to_string())
    }

    fn close(&mut self) {
        if let Some(mut c) = self.ctl.take() {
            c.set_timeout(2);
            // Dropped without a QUIT in TLS: many servers drop the connection after QUIT without a close_notify
            // anyway, and the work is done or has failed by now.
            let _ = c.send("QUIT");
        }
    }

    fn delete(&mut self, name: &str) -> Result<(), String> {
        let r = self.ctl()?.cmd(&format!("DELE {name}"))?;
        if r.ok() { Ok(()) } else { Err(r.text()) }
    }

    /// The size the server reports, or None when it will not say plainly (no SIZE, or an odd reply).
    fn size_of(&mut self, name: &str) -> Option<u64> {
        // SIZE only counts bytes in binary mode; vsftpd refuses it in ASCII mode, which a listing leaves behind.
        let _ = self.ctl().ok()?.cmd("TYPE I");
        let r = self.ctl().ok()?.cmd(&format!("SIZE {name}")).ok()?;
        let l = r.last();
        let rest = l.strip_prefix("213 ")?;
        rest.trim_end().parse().ok().filter(|_| rest.trim_end().bytes().all(|b| b.is_ascii_digit()))
    }

    /// PASV/EPSV: the address the data connection goes to, or the server's refusal.
    fn passive_target(&mut self, host: &str) -> Result<Result<SocketAddr, Reply>, String> {
        let v6 = self.ctl()?.peer.is_ipv6();
        if v6 {
            let r = self.ctl()?.cmd("EPSV")?;
            let peer = self.ctl()?.peer;
            if r.code == 229 {
                if let Some(port) = r.last().split('|').nth(3).and_then(|p| p.trim().parse::<u16>().ok()) {
                    return Ok(Ok(SocketAddr::new(peer.ip(), port)));
                }
            }
            return Ok(Err(r));
        }
        let r = self.ctl()?.cmd("PASV")?;
        let peer = self.ctl()?.peer;
        match parse_pasv(r.last()) {
            Some((ip, port)) if r.code == 227 => {
                self.advertised = Some(ip.to_string());
                let addr = if self.using_pasv_address { IpAddr::V4(ip) } else { peer.ip() };
                let _ = host;
                Ok(Ok(SocketAddr::new(addr, port)))
            }
            _ => Ok(Err(r)),
        }
    }

    /// Start a transfer: TYPE, the data connection (passive, or active when the server refused passive), the command,
    /// and the 1xx reply. The returned stream is the data connection, TLS wrapped when the control connection is.
    fn begin(&mut self, host: &str, ty: &str, command: &str, data_timeout: u64) -> Result<Stream, Xfer> {
        let _ = self.ctl().map_err(Xfer::Fail)?.cmd(&format!("TYPE {ty}")).map_err(Xfer::Fail)?;
        let tls = self.cfg.is_some() && matches!(self.ctl.as_ref().map(|c| c.r.get_ref()), Some(Stream::Tls(_)));
        let sock = if !self.active {
            match self.passive_target(host).map_err(Xfer::Fail)? {
                Ok(addr) => {
                    TcpStream::connect_timeout(&addr, Duration::from_secs(TIMEOUT)).map_err(|_| Xfer::Fail(NO_DATA_CONNECTION.to_string()))?
                }
                Err(r) => return Err(Xfer::Refused(r)),
            }
        } else {
            return self.begin_active(ty, command, data_timeout, tls);
        };
        let _ = sock.set_read_timeout(Some(Duration::from_secs(data_timeout)));
        let _ = sock.set_write_timeout(Some(Duration::from_secs(data_timeout)));
        let r = self.ctl().map_err(Xfer::Fail)?.cmd(command).map_err(Xfer::Fail)?;
        if !(100..200).contains(&r.code) {
            return Err(Xfer::Refused(r));
        }
        self.wrap(sock, tls).map_err(Xfer::Fail)
    }

    fn begin_active(&mut self, _ty: &str, command: &str, data_timeout: u64, tls: bool) -> Result<Stream, Xfer> {
        let local = self.ctl().map_err(Xfer::Fail)?.local;
        let listener = TcpListener::bind(SocketAddr::new(local.ip(), 0)).map_err(|e| Xfer::Fail(io_text(&e)))?;
        let port = listener.local_addr().map_err(|e| Xfer::Fail(io_text(&e)))?.port();
        let port_cmd = match local.ip() {
            IpAddr::V4(ip) => {
                let o = ip.octets();
                format!("PORT {},{},{},{},{},{}", o[0], o[1], o[2], o[3], port >> 8, port & 255)
            }
            IpAddr::V6(ip) => format!("EPRT |2|{ip}|{port}|"),
        };
        let r = self.ctl().map_err(Xfer::Fail)?.cmd(&port_cmd).map_err(Xfer::Fail)?;
        if !r.ok() {
            return Err(Xfer::Refused(r));
        }
        let r = self.ctl().map_err(Xfer::Fail)?.cmd(command).map_err(Xfer::Fail)?;
        if !(100..200).contains(&r.code) {
            return Err(Xfer::Refused(r));
        }
        listener.set_nonblocking(true).map_err(|e| Xfer::Fail(io_text(&e)))?;
        let started = Instant::now();
        let sock = loop {
            match listener.accept() {
                Ok((s, _)) => break s,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock && started.elapsed() < Duration::from_secs(TIMEOUT) => std::thread::sleep(Duration::from_millis(20)),
                Err(_) => return Err(Xfer::Fail("the server did not connect back to accept the data connection".into())),
            }
        };
        let _ = sock.set_nonblocking(false);
        let _ = sock.set_read_timeout(Some(Duration::from_secs(data_timeout)));
        let _ = sock.set_write_timeout(Some(Duration::from_secs(data_timeout)));
        self.wrap(sock, tls).map_err(Xfer::Fail)
    }

    fn wrap(&mut self, sock: TcpStream, tls: bool) -> Result<Stream, String> {
        if !tls {
            return Ok(Stream::Plain(sock));
        }
        let ctl = self.ctl()?;
        let conn = ClientConnection::new(ctl.cfg.clone().ok_or("TLS is not available")?, ctl.name.clone()).map_err(|e| format!("handshake failed: {e}"))?;
        Ok(Stream::Tls(Box::new(StreamOwned::new(conn, sock))))
    }

    /// Everything the data connection sends, then the server's closing reply.
    fn read_all(&mut self, mut data: Stream) -> Result<(Vec<u8>, Reply), String> {
        let mut buf = vec![];
        match data.read_to_end(&mut buf) {
            Ok(_) => {}
            // a server that drops the TLS connection without a close_notify has still sent what it sent
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {}
            Err(e) => return Err(if matches!(data, Stream::Tls(_)) && !timeoutish(&e) { format!("SSL read failed: {}", io_text(&e)) } else { io_text(&e) }),
        }
        drop(data);
        let r = self.ctl()?.reply()?;
        Ok((buf, r))
    }

    fn lines(&mut self, host: &str, command: &str) -> Result<Vec<String>, Xfer> {
        let data = self.begin(host, "A", command, TIMEOUT)?;
        let (buf, r) = self.read_all(data).map_err(Xfer::Fail)?;
        if !r.ok() {
            return Err(Xfer::Refused(r));
        }
        Ok(String::from_utf8_lossy(&buf).lines().map(|l| l.trim_end_matches('\r').to_string()).filter(|l| !l.is_empty()).collect())
    }

    /// STOR. Err is the text PHP's warnings would carry.
    fn store(&mut self, host: &str, local: &Path, name: &str, timeout: u64) -> Result<(), String> {
        let mut file = std::fs::File::open(local).map_err(|e| format!("cannot read {}: {}", local.display(), io_text(&e)))?;
        self.ctl()?.set_timeout(timeout);
        let r = (|| {
            let mut data = match self.begin(host, "I", &format!("STOR {name}"), timeout) {
                Ok(d) => d,
                Err(Xfer::Refused(r)) => return Err(r.text()),
                Err(Xfer::Fail(m)) => return Err(m),
            };
            let sent = std::io::copy(&mut file, &mut data).and_then(|_| data.flush());
            if let Err(e) = sent {
                return Err(if timeoutish(&e) { "timed out".to_string() } else { io_text(&e) });
            }
            match &mut data {
                Stream::Tls(s) => {
                    s.conn.send_close_notify();
                    let _ = s.conn.complete_io(&mut s.sock);
                    let _ = s.sock.shutdown(std::net::Shutdown::Write);
                }
                Stream::Plain(s) => {
                    let _ = s.shutdown(std::net::Shutdown::Write);
                }
                Stream::Gone => {}
            }
            drop(data);
            let r = self.ctl()?.reply()?;
            if r.ok() { Ok(()) } else { Err(r.text()) }
        })();
        if let Ok(c) = self.ctl() {
            c.set_timeout(TIMEOUT);
        }
        r
    }
}

fn parse_pasv(line: &str) -> Option<(Ipv4Addr, u16)> {
    let re = regex::Regex::new(r"(\d{1,3}),(\d{1,3}),(\d{1,3}),(\d{1,3}),(\d{1,3}),(\d{1,3})").ok()?;
    let m = re.captures(line)?;
    let n = |i: usize| m[i].parse::<u16>().ok().filter(|v| *v <= 255);
    Some((Ipv4Addr::new(n(1)? as u8, n(2)? as u8, n(3)? as u8, n(4)? as u8), n(5)? * 256 + n(6)?))
}

// ---------------------------------------------------------------------------------------------------- client ---

struct Client<'a> {
    cfg: &'a Ftp,
    host: String,
    port: u16,
    path: String,
    /// Whether data connections use the PASV reply's address, once a listing has shown which works.
    pasv_address: Cell<Option<bool>>,
}

impl<'a> Client<'a> {
    fn new(cfg: &'a Ftp) -> Client<'a> {
        Client {
            cfg,
            host: cfg.host.trim().trim_matches(|c| c == '[' || c == ']').trim().to_string(),
            port: if cfg.port > 0 { cfg.port } else { 21 },
            path: cfg.path.trim_matches(|c| c == '/' || c == ' ').to_string(),
            pasv_address: Cell::new(None),
        }
    }

    /// host:port, with an IPv6 address in brackets.
    fn where_(&self) -> String {
        if self.host.parse::<std::net::Ipv6Addr>().is_ok() { format!("[{}]:{}", self.host, self.port) } else { format!("{}:{}", self.host, self.port) }
    }

    fn label(&self) -> String {
        format!("{}{}{}", if self.cfg.tls { "FTPS " } else { "FTP " }, self.where_(), if self.path.is_empty() { String::new() } else { format!("/{}", self.path) })
    }

    fn open(&self, wait: u64) -> Result<(TcpStream, SocketAddr), String> {
        let addrs: Vec<SocketAddr> = (self.host.as_str(), self.port).to_socket_addrs().map_err(|e| io_text(&e)).map_err(|e| if e.is_empty() { "host not found".into() } else { e })?.collect();
        let mut last = "no address".to_string();
        for a in addrs {
            match TcpStream::connect_timeout(&a, Duration::from_secs(wait)) {
                Ok(s) => return Ok((s, a)),
                Err(e) => last = io_text(&e),
            }
        }
        Err(last)
    }

    fn connect(&self) -> Result<Conn, String> {
        if self.host.is_empty() {
            return Err("The FTP host is empty.".into());
        }
        let started = Instant::now();
        let (sock, peer) = self.open(TIMEOUT).map_err(|e| self.unreachable(&e, started.elapsed()))?;
        let local = sock.local_addr().map_err(|e| io_text(&e))?;
        let cfg = if self.cfg.tls { Some(tls_config()?) } else { None };
        let name = ServerName::try_from(self.host.clone()).map_err(|_| format!("The FTP host {} is not a valid name for TLS.", self.host))?;
        let mut ctl = Control { r: BufReader::new(Stream::Plain(sock)), cfg: cfg.clone(), name, peer, local };
        ctl.set_timeout(TIMEOUT);

        // The greeting.
        let g = match ctl.reply() {
            Ok(r) => r,
            Err(e) if e == "timed out" => return Err(self.no_greeting()),
            Err(e) => return Err(if e.contains("closed") { format!("{} closed the connection straight away.", self.where_()) } else { format!("Cannot reach {}: {e}.", self.where_()) }),
        };
        if g.code != 220 {
            let line = g.last().trim_end_matches(|c| c == '.' || c == ' ').to_string();
            if line.starts_with("SSH-") {
                return Err(format!("{} is an SSH server. SFTP is not supported; use FTP or explicit FTPS (AUTH TLS), usually on port 21.", self.where_()));
            }
            return Err(format!("{} turned the connection away: {line}.", self.where_()));
        }

        let mut conn = Conn { ctl: None, cfg: cfg.clone(), active: false, using_pasv_address: false, advertised: None, host_address: String::new() };

        // With TLS on, AUTH TLS, the handshake and PROT P come before USER.
        let mut login_err: Option<String> = None;
        if self.cfg.tls {
            let mut auth = ctl.cmd("AUTH TLS").map_err(|e| self.login_failure(&e))?;
            if auth.code != 234 {
                let tls_line = auth.last().trim_end_matches(|c| c == '.' || c == ' ').to_string();
                auth = ctl.cmd("AUTH SSL").map_err(|e| self.login_failure(&e))?;
                if auth.code != 234 {
                    return Err(format!("{} does not offer explicit FTPS (AUTH TLS answered: {tls_line}). Turn TLS off to use plain FTP, which sends the password in clear.", self.where_()));
                }
            }
            if let Err(e) = ctl.upgrade() {
                return Err(self.login_failure(&e));
            }
            let _ = ctl.cmd("PBSZ 0");
            let _ = ctl.cmd("PROT P");
        }

        let login = |ctl: &mut Control| -> Result<(), String> {
            let r = ctl.cmd(&format!("USER {}", self.cfg.username))?;
            let r = match r.code {
                331 | 332 => ctl.cmd(&format!("PASS {}", self.cfg.password))?,
                _ => r,
            };
            if r.ok() { Ok(()) } else { Err(r.text()) }
        };
        if let Err(e) = login(&mut ctl) {
            login_err = Some(e);
        }
        if let Some(e) = login_err {
            let _ = ctl.send("QUIT");
            return Err(self.login_failure(&e));
        }

        // PROT P was asked for before USER; the archive holds the app key, so ask again after login and stop on a
        // refusal. A server that only takes PROT P after login says yes here while the first one went unanswered;
        // the listing before every upload catches a data connection that does not match.
        if self.cfg.tls {
            let _ = ctl.cmd("PBSZ 0");
            let last = match ctl.cmd("PROT P") {
                Ok(r) if r.ok() => None,
                Ok(r) => Some(r.last().trim_end_matches(|c| c == '.' || c == ' ').to_string()),
                Err(e) => Some(e),
            };
            if let Some(last) = last {
                let _ = ctl.send("QUIT");
                return Err(format!("The FTP server did not accept PROT P{}, so data connections would not be encrypted. Nothing was sent. If the server only accepts PROT P after login, this FTP client cannot encrypt for it: change the server, or turn TLS off and accept plain FTP.", if last.is_empty() { String::new() } else { format!(" ({last})") }));
            }
        }

        conn.host_address = if self.host.parse::<IpAddr>().is_ok() { self.host.clone() } else { peer.ip().to_string() };
        conn.ctl = Some(ctl);

        // Ask for a passive address once, to decide which address data connections use; a refusal means active mode.
        let active_needed;
        match conn.passive_target(&self.host) {
            Ok(Ok(_)) => {
                active_needed = false;
                conn.using_pasv_address = match self.pasv_address.get() {
                    Some(v) => v,
                    None => conn.advertised.as_deref().map(|a| use_pasv_address(a, &conn.host_address)).unwrap_or(false),
                };
            }
            _ => active_needed = true,
        }
        conn.active = active_needed;

        // Walk the path one directory at a time, creating what is missing, so a fresh server needs no preparation.
        let mut walked: Vec<&str> = vec![];
        for seg in self.path.split('/').filter(|s| !s.is_empty()) {
            walked.push(seg);
            let ctl = conn.ctl()?;
            if ctl.cmd(&format!("CWD {seg}")).map(|r| r.ok()).unwrap_or(false) {
                continue;
            }
            let mk = ctl.cmd(&format!("MKD {seg}"));
            let refused = match &mk {
                Ok(r) if !r.ok() => r.text(),
                Err(e) => e.clone(),
                _ => String::new(),
            };
            let entered = mk.map(|r| r.ok()).unwrap_or(false) && conn.ctl()?.cmd(&format!("CWD {seg}")).map(|r| r.ok()).unwrap_or(false);
            if !entered {
                let e = failure(&format!("Cannot enter or create the FTP directory {}", walked.join("/")), &refused, "");
                conn.close();
                return Err(e);
            }
        }
        Ok(conn)
    }

    /// Why the connection gave up, from the error, how long it took, or a second look.
    fn unreachable(&self, err: &str, took: Duration) -> String {
        let where_ = self.where_();
        if err == "timed out" || took >= Duration::from_secs(TIMEOUT - 1) {
            return format!("Cannot reach {where_}: no answer within {TIMEOUT} seconds. Check the host, the port and any firewall in between.");
        }
        if err.to_lowercase().contains("refused") {
            return format!("Cannot reach {where_}: {err}. Check the host and the port.");
        }
        format!("Cannot reach {where_}: {err}.")
    }

    /// Connected, but no "220" greeting within the timeout. An SSH server greets straight away with something else;
    /// an implicit FTPS one waits.
    fn no_greeting(&self) -> String {
        format!("{} accepted the connection but sent no FTP greeting within {TIMEOUT} seconds. If it expects implicit FTPS (usually port 990), that is not supported: use explicit FTPS (AUTH TLS), usually on port 21.", self.where_())
    }

    fn login_failure(&self, reply: &str) -> String {
        let where_ = self.where_();
        if self.cfg.tls {
            if reply.contains("handshake failed") {
                return format!("The TLS handshake with {where_} failed. CortenDesk needs TLS 1.2 or later; check that the FTP server offers it.");
            }
            if reply.contains("SSL read failed") || reply.contains("SSL write failed") || reply.contains("connection closed") {
                return format!("{where_} closed the TLS session during login ({reply}). Two common causes: the server failing right after login, such as vsftpd refusing a writable chroot directory (\"500 OOPS\"), or a server that requires a client certificate, which is not supported.");
            }
        }
        let reply = tidy(reply);
        if reply.is_empty() {
            return "FTP login failed. Check the username and password.".into();
        }
        let tls_hint = !self.cfg.tls && regex::Regex::new(r"(?i)\b(TLS|SSL|encrypt)").map(|r| r.is_match(&reply)).unwrap_or(false);
        format!("FTP login failed: {reply}.{}", if tls_hint { " Turn TLS on." } else { "" })
    }

    fn active_hint(&self) -> &'static str {
        "The server refused passive mode, so active mode was tried; that needs the server to accept PORT and to connect back to this host"
    }

    fn names(&self, conn: &mut Conn) -> Result<Vec<String>, String> {
        let mut entries = conn.lines(&self.host, "NLST .");

        // The first listing settles which address data connections use. When the one picked does not open and the
        // server named another, try that: behind something that forwards only port 21, the server's own address is
        // the right one even when it is private.
        let no_data = matches!(&entries, Err(Xfer::Fail(m)) if m == NO_DATA_CONNECTION);
        if no_data && self.pasv_address.get().is_none() && !conn.active && conn.advertised.is_some() && conn.advertised.as_deref() != Some(conn.host_address.as_str()) {
            conn.using_pasv_address = !conn.using_pasv_address;
            entries = conn.lines(&self.host, "NLST .");
        }
        if !matches!(&entries, Err(Xfer::Fail(m)) if m == NO_DATA_CONNECTION) && self.pasv_address.get().is_none() {
            self.pasv_address.set(Some(conn.using_pasv_address));
        }

        match entries {
            Ok(lines) => Ok(basenames(lines)),
            Err(Xfer::Refused(_)) => {
                // Any error reply to NLST is a bare failure with no detail, and some servers answer NLST that way for
                // an empty directory. LIST tells an empty directory from a refusal.
                match conn.lines(&self.host, "LIST .") {
                    Ok(raw) => {
                        let rest: Vec<&String> = raw.iter().filter(|l| !is_empty_dir_line(l)).collect();
                        if rest.is_empty() {
                            return Ok(vec![]);
                        }
                        Err(failure("FTP directory listing failed", "", if conn.active { "The server refused passive mode, so active mode was tried; that needs the server to accept PORT and to connect back to this host. If that works, check that the account may list the directory" } else { "Check that the account may list the directory" }))
                    }
                    Err(_) => Err(failure("FTP directory listing failed", "", if conn.active { "The server refused passive mode, so active mode was tried; that needs the server to accept PORT and to connect back to this host. If that works, check that the account may list the directory" } else { "Check that the account may list the directory" })),
                }
            }
            Err(Xfer::Fail(m)) => {
                let timed_out = self.cfg.tls && regex::Regex::new(r"(?i)timed out|handshake failed").map(|r| r.is_match(&m)).unwrap_or(false);
                let hint = if conn.active {
                    self.active_hint()
                } else if timed_out {
                    "With FTPS this can mean the server accepts PROT P only after login, which this FTP client cannot work with"
                } else {
                    ""
                };
                Err(failure("FTP directory listing failed", &m, hint))
            }
        }
    }

    fn put_on(&self, conn: &mut Conn, local: &Path, name: &str) -> Result<(), String> {
        let size = std::fs::metadata(local).map_err(|e| format!("cannot read {}: {}", local.display(), io_text(&e)))?.len();
        let mut existed = self.names(conn)?.iter().any(|n| n == name);
        if existed {
            let remote = conn.size_of(name);
            if remote == Some(size) {
                return Ok(());
            }
            // A copy known to be short goes first: a server that refuses overwrites, or stores a clashing upload
            // under another name, would otherwise keep it.
            if remote.is_some() && conn.delete(name).is_ok() {
                existed = false;
            }
        }
        self.upload(conn, local, name, existed, UPLOAD_TIMEOUT).map(|_| ())
    }

    fn test_on(&self, conn: &mut Conn) -> Result<String, String> {
        let pwd = conn.ctl().ok().and_then(|c| c.cmd("PWD").ok()).filter(|r| r.code == 257).and_then(|r| {
            let l = r.last().to_string();
            let a = l.find('"')?;
            let b = l.rfind('"')?;
            (b > a).then(|| l[a + 1..b].to_string())
        });
        self.names(conn)?;

        let name = format!("cortendesk-write-test-{}.tmp", hex::encode(rand::random::<[u8; 3]>()));
        let dir = std::env::temp_dir();
        let file = dir.join(format!("ftp-test-{}", hex::encode(rand::random::<[u8; 6]>())));
        std::fs::write(&file, "CortenDesk connection test. Safe to delete.\n").map_err(|e| format!("cannot write a temporary file: {}", io_text(&e)))?;
        let up = self.upload(conn, &file, &name, false, TIMEOUT);
        let _ = std::fs::remove_file(&file);
        if !up? {
            // The server confirmed late and the connection was closed.
            *conn = self.connect()?;
        }
        if let Err(d) = conn.delete(&name) {
            return Err(failure(&format!("Listing and upload work, but deleting {name} failed"), &d, "Remove it by hand. The off-site copy needs delete permission to drop pruned backups"));
        }
        Ok(format!("Connected to {}{}. Listing, upload and delete work.{}", self.label(), pwd.map(|p| format!(" (directory {p})")).unwrap_or_default(), if conn.active { " The server refused passive mode, so active mode is used." } else { "" }))
    }

    /// Upload, then compare the size the server reports, so a short file does not pass for a finished copy. Whatever a
    /// failed upload left behind is removed, but never a file that was there before. Returns false when the upload
    /// succeeded only on a second look and `conn` has been closed.
    fn upload(&self, conn: &mut Conn, local: &Path, name: &str, existed: bool, timeout: u64) -> Result<bool, String> {
        let size = std::fs::metadata(local).map(|m| m.len()).unwrap_or(0);
        let sent = conn.store(&self.host, local, name, timeout);
        let Err(detail) = sent else {
            let remote = conn.size_of(name);
            if let Some(remote) = remote {
                if remote != size {
                    let removed = conn.delete(name).is_ok();
                    return Err(format!("FTP upload of {name}: the server reports {remote} bytes instead of {size}; {}", if removed { "it was removed." } else { "the next run replaces it." }));
                }
            }
            return Ok(true);
        };

        let low = detail.to_lowercase();
        let transport = tidy(&detail).is_empty() || ["timed out", "did not open", "accept", "establish", "data connection", "n't connect", "not connect", "connect back"].iter().any(|k| low.contains(k));
        let timed_out = low.contains("timed out");
        let mut e = failure(&format!("FTP upload of {name} failed"), &detail, if conn.active && transport { self.active_hint() } else { "" });

        // When a transfer breaks off, the server's final reply may still be on its way. Read the real one; a 500 or 502
        // is the server not knowing NOOP, not news about the upload.
        let first = match conn.ctl() {
            Ok(c) => {
                c.set_timeout(TIMEOUT);
                c.cmd("NOOP").map(|r| r.lines.first().cloned().unwrap_or_default()).unwrap_or_default()
            }
            Err(_) => String::new(),
        };
        let refused = (first.len() > 4 && (first.starts_with('4') || first.starts_with('5')) && !first.starts_with("500") && !first.starts_with("502") && matches!(first.as_bytes()[3], b' ' | b'-')).then(|| first[4..].to_string());
        if let Some(m) = &refused {
            e = format!("FTP upload of {name} failed: {}.", m.trim_end_matches(|c| c == '.' || c == ' '));
        }
        // Only a confirmation that came late, or none at all, can mean the server has the file after all. A refusal
        // stands, however late it came.
        let may_be_complete = refused.is_none() && (timed_out || first.starts_with("226") || first.starts_with("250"));
        // The connection may be a reply behind now; it is closed first so a server allowing one connection per
        // address lets the cleanup in.
        conn.close();
        if !existed {
            let state = self.settle(name, size, may_be_complete);
            if state == "done" {
                return Ok(false);
            }
            let base = e.trim_end_matches('.').to_string();
            e = match state {
                "short" => format!("{base}. A partial copy is left on the server; the next run replaces it."),
                "kept" => format!("{base}; the server kept a full-size {name} that could not be removed. The next run counts it as copied, so remove it by hand."),
                "unknown" => format!("{base}; a partial {name} may remain on the server. If the server does not report file sizes, remove it by hand, or the next run counts it as copied."),
                _ => e,
            };
        }
        Err(e)
    }

    /// After a failed upload, look again over a fresh connection. When the failure may have been only a late
    /// confirmation, the full size there means the server finished after all. Anything else is removed. Returns done,
    /// removed, short (left, shorter), kept (left, full size but refused) or unknown.
    fn settle(&self, name: &str, size: u64, may_be_complete: bool) -> &'static str {
        let Ok(mut conn) = self.connect() else { return "unknown" };
        let r = (|| {
            if !self.names(&mut conn).ok()?.iter().any(|n| n == name) {
                return Some("removed");
            }
            let remote = conn.size_of(name);
            if may_be_complete && remote == Some(size) {
                return Some("done");
            }
            if conn.delete(name).is_ok() {
                return Some("removed");
            }
            Some(match remote {
                None => "unknown",
                Some(r) if r == size => "kept",
                Some(_) => "short",
            })
        })();
        conn.close();
        r.unwrap_or("unknown")
    }
}

/// Servers differ on whether NLST returns bare names or paths.
fn basenames(lines: Vec<String>) -> Vec<String> {
    lines
        .into_iter()
        .map(|e| e.trim_end_matches('/').rsplit('/').next().unwrap_or("").to_string())
        .filter(|n| !n.is_empty() && n != "." && n != "..")
        .collect()
}

/// `total 0`, or a line ending in a lone `.` / `..` entry.
fn is_empty_dir_line(l: &str) -> bool {
    let t = l.trim();
    if let Some(n) = t.strip_prefix("total ") {
        if !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()) {
            return true;
        }
    }
    let last = t.rsplit(char::is_whitespace).next().unwrap_or("");
    t.contains(char::is_whitespace) && (last == "." || last == "..")
}

// ------------------------------------------------------------------------------------------------------ tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::Mutex;

    #[derive(Default)]
    struct Fs {
        dirs: BTreeSet<String>,
        files: BTreeMap<String, Vec<u8>>,
    }

    struct Fake {
        port: u16,
        fs: Arc<Mutex<Fs>>,
    }

    /// A small in-process FTP server: USER/PASS, PWD, CWD, MKD, TYPE, PASV (or refusing it), NLST, LIST, SIZE, STOR,
    /// DELE, NOOP, QUIT. One directory level below the root.
    fn serve(password: &'static str, refuse_pasv: bool, no_size: bool) -> Fake {
        serve_with(password, refuse_pasv, no_size, None)
    }

    /// The same server with explicit FTPS: AUTH TLS on a self-signed certificate, PBSZ/PROT P, TLS on the data
    /// connections.
    fn serve_tls(password: &'static str) -> Fake {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string(), "127.0.0.1".to_string()]).unwrap();
        let der = cert.cert.der().clone();
        let key = rustls::pki_types::PrivateKeyDer::try_from(cert.key_pair.serialize_der()).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let cfg = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS12, &rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![der], key)
            .unwrap();
        serve_with(password, false, false, Some(Arc::new(cfg)))
    }

    /// A control or data connection of the fake server, plain or TLS.
    enum Ctl {
        Plain(TcpStream),
        Tls(Box<StreamOwned<rustls::ServerConnection, TcpStream>>),
        Gone,
    }
    impl Read for Ctl {
        fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
            match self {
                Ctl::Plain(s) => s.read(b),
                Ctl::Tls(s) => s.read(b),
                Ctl::Gone => Ok(0),
            }
        }
    }
    impl Write for Ctl {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            match self {
                Ctl::Plain(s) => s.write(b),
                Ctl::Tls(s) => s.write(b),
                Ctl::Gone => Ok(b.len()),
            }
        }
        fn flush(&mut self) -> std::io::Result<()> {
            match self {
                Ctl::Plain(s) => s.flush(),
                Ctl::Tls(s) => s.flush(),
                Ctl::Gone => Ok(()),
            }
        }
    }
    fn finish(d: Ctl) {
        if let Ctl::Tls(mut s) = d {
            s.conn.send_close_notify();
            let _ = s.conn.complete_io(&mut s.sock);
        }
    }

    fn serve_with(password: &'static str, refuse_pasv: bool, no_size: bool, tls: Option<Arc<rustls::ServerConfig>>) -> Fake {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let fs = Arc::new(Mutex::new(Fs::default()));
        let fs2 = fs.clone();
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                let Ok(conn) = conn else { return };
                let fs = fs2.clone();
                let tls = tls.clone();
                std::thread::spawn(move || session(conn, fs, password, refuse_pasv, no_size, tls));
            }
        });
        Fake { port, fs }
    }

    fn session(conn: TcpStream, fs: Arc<Mutex<Fs>>, password: &'static str, refuse_pasv: bool, no_size: bool, tls: Option<Arc<rustls::ServerConfig>>) {
        let mut r = BufReader::new(Ctl::Plain(conn));
        let say = |r: &mut BufReader<Ctl>, s: &str| {
            let w = r.get_mut();
            let _ = w.write_all(format!("{s}\r\n").as_bytes());
            let _ = w.flush();
        };
        let mut prot_p = false;
        say(&mut r, "220 fake ready");
        let mut cwd = String::new();
        let mut user_ok = false;
        let mut data: Option<TcpListener> = None;
        let mut active: Option<SocketAddr> = None;
        loop {
            let mut line = String::new();
            if r.read_line(&mut line).unwrap_or(0) == 0 {
                return;
            }
            let line = line.trim_end().to_string();
            let (verb, arg) = line.split_once(' ').unwrap_or((line.as_str(), ""));
            let key = |name: &str| if cwd.is_empty() { name.to_string() } else { format!("{cwd}/{name}") };
            match verb.to_uppercase().as_str() {
                "AUTH" => match &tls {
                    None => say(&mut r, "500 AUTH not understood"),
                    Some(cfg) => {
                        say(&mut r, "234 go ahead");
                        let Ctl::Plain(sock) = std::mem::replace(r.get_mut(), Ctl::Gone) else { return };
                        *r.get_mut() = Ctl::Tls(Box::new(StreamOwned::new(rustls::ServerConnection::new(cfg.clone()).unwrap(), sock)));
                    }
                },
                "PROT" => {
                    prot_p = arg == "P";
                    say(&mut r, "200 ok");
                }
                "USER" => {
                    user_ok = arg == "alice";
                    say(&mut r, "331 password please");
                }
                "PASS" => {
                    if user_ok && arg == password {
                        say(&mut r, "230 welcome")
                    } else {
                        say(&mut r, "530 Login incorrect.")
                    }
                }
                "PWD" => say(&mut r, &format!("257 \"/{cwd}\" is the current directory")),
                "TYPE" | "NOOP" | "PBSZ" => say(&mut r, "200 ok"),
                "CWD" => {
                    if arg == ".." {
                        cwd.clear();
                        say(&mut r, "250 ok");
                    } else if fs.lock().unwrap().dirs.contains(&key(arg)) {
                        cwd = key(arg);
                        say(&mut r, "250 ok");
                    } else {
                        say(&mut r, "550 No such directory.");
                    }
                }
                "MKD" => {
                    fs.lock().unwrap().dirs.insert(key(arg));
                    say(&mut r, "257 created");
                }
                "PASV" => {
                    if refuse_pasv {
                        say(&mut r, "502 PASV not available");
                    } else {
                        let l = TcpListener::bind("127.0.0.1:0").unwrap();
                        let p = l.local_addr().unwrap().port();
                        data = Some(l);
                        say(&mut r, &format!("227 Entering Passive Mode (127,0,0,1,{},{})", p >> 8, p & 255));
                    }
                }
                "PORT" => {
                    let n: Vec<u16> = arg.split(',').map(|x| x.parse().unwrap()).collect();
                    active = Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(n[0] as u8, n[1] as u8, n[2] as u8, n[3] as u8)), n[4] * 256 + n[5]));
                    say(&mut r, "200 PORT ok");
                }
                "NLST" | "LIST" | "STOR" => {
                    let open = |data: &mut Option<TcpListener>, active: &mut Option<SocketAddr>| -> Option<Ctl> {
                        let sock = if let Some(a) = active.take() { TcpStream::connect(a).ok() } else { data.take().and_then(|l| l.accept().ok().map(|(s, _)| s)) }?;
                        Some(match (&tls, prot_p) {
                            (Some(cfg), true) => Ctl::Tls(Box::new(StreamOwned::new(rustls::ServerConnection::new(cfg.clone()).unwrap(), sock))),
                            _ => Ctl::Plain(sock),
                        })
                    };
                    let Some(mut d) = open(&mut data, &mut active) else {
                        say(&mut r, "425 Can't open data connection");
                        continue;
                    };
                    say(&mut r, "150 here it comes");
                    if verb.eq_ignore_ascii_case("STOR") {
                        let mut buf = vec![];
                        let _ = d.read_to_end(&mut buf);
                        finish(d);
                        fs.lock().unwrap().files.insert(key(arg), buf);
                        say(&mut r, "226 stored");
                    } else {
                        let prefix = if cwd.is_empty() { String::new() } else { format!("{cwd}/") };
                        let names: Vec<(String, usize)> = fs.lock().unwrap().files.iter().filter_map(|(k, v)| k.strip_prefix(&prefix).filter(|r| !r.contains('/')).map(|r| (r.to_string(), v.len()))).collect();
                        let body: String = if verb.eq_ignore_ascii_case("NLST") {
                            names.iter().map(|(n, _)| format!("{n}\r\n")).collect()
                        } else {
                            names.iter().map(|(n, s)| format!("-rw-r--r-- 1 u g {s} Jan 1 00:00 {n}\r\n")).collect()
                        };
                        if verb.eq_ignore_ascii_case("NLST") && names.is_empty() {
                            // like several servers: an error reply for an empty directory
                            finish(d);
                            say(&mut r, "550 No files found");
                            continue;
                        }
                        let _ = d.write_all(body.as_bytes());
                        let _ = d.flush();
                        finish(d);
                        say(&mut r, "226 done");
                    }
                }
                "SIZE" => {
                    let size = fs.lock().unwrap().files.get(&key(arg)).map(|v| v.len());
                    match (size, no_size) {
                        (Some(s), false) => say(&mut r, &format!("213 {s}")),
                        _ => say(&mut r, "550 no size"),
                    }
                }
                "DELE" => {
                    if fs.lock().unwrap().files.remove(&key(arg)).is_some() {
                        say(&mut r, "250 deleted")
                    } else {
                        say(&mut r, "550 No such file.")
                    }
                }
                "QUIT" => {
                    say(&mut r, "221 bye");
                    return;
                }
                _ => say(&mut r, "502 not implemented"),
            }
        }
    }

    fn ftp(f: &Fake, password: &str, path: &str) -> Ftp {
        Ftp { host: "127.0.0.1".into(), port: f.port, username: "alice".into(), password: password.into(), path: path.into(), tls: false }
    }

    fn archive(dir: &Path, name: &str, body: &[u8]) -> std::path::PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, body).unwrap();
        p
    }

    #[test]
    fn put_list_delete_and_test_against_a_fake_server() {
        let f = serve("secret", false, false);
        let t = ftp(&f, "secret", "backups/hte");
        let tmp = tempfile::tempdir().unwrap();
        let local = archive(tmp.path(), "cortendesk-backup-20260101-030000.tar", &[7u8; 5000]);

        // the directory is created on the way in, an empty listing is an empty list
        assert_eq!(t.list().unwrap(), vec![]);
        assert!(f.fs.lock().unwrap().dirs.contains("backups/hte"));

        t.put(&local, "cortendesk-backup-20260101-030000.tar").unwrap();
        assert_eq!(f.fs.lock().unwrap().files["backups/hte/cortendesk-backup-20260101-030000.tar"].len(), 5000);
        assert_eq!(t.list().unwrap(), vec![("cortendesk-backup-20260101-030000.tar".to_string(), Some(5000))]);

        // the same size already there: nothing is sent again
        f.fs.lock().unwrap().files.insert("backups/hte/cortendesk-backup-20260101-030000.tar".into(), vec![7u8; 5000]);
        t.put(&local, "cortendesk-backup-20260101-030000.tar").unwrap();

        // a short copy is replaced
        f.fs.lock().unwrap().files.insert("backups/hte/cortendesk-backup-20260101-030000.tar".into(), vec![0u8; 10]);
        t.put(&local, "cortendesk-backup-20260101-030000.tar").unwrap();
        assert_eq!(f.fs.lock().unwrap().files["backups/hte/cortendesk-backup-20260101-030000.tar"].len(), 5000);

        let msg = t.test().unwrap();
        assert!(msg.starts_with("Connected to FTP 127.0.0.1:"), "{msg}");
        assert!(msg.contains("/backups/hte") && msg.ends_with("Listing, upload and delete work."), "{msg}");
        // the test file is gone again
        assert_eq!(f.fs.lock().unwrap().files.len(), 1);

        t.delete("cortendesk-backup-20260101-030000.tar").unwrap();
        assert!(f.fs.lock().unwrap().files.is_empty());
        let e = t.delete("cortendesk-backup-20260101-030000.tar").unwrap_err();
        assert_eq!(e, "FTP delete of cortendesk-backup-20260101-030000.tar failed: No such file.");
    }

    #[test]
    fn a_wrong_password_and_an_unreachable_host_are_reported_in_words() {
        let f = serve("secret", false, false);
        assert_eq!(ftp(&f, "nope", "").test().unwrap_err(), "FTP login failed: Login incorrect.");

        let dead = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = dead.local_addr().unwrap().port();
        drop(dead);
        let t = Ftp { host: "127.0.0.1".into(), port, username: "a".into(), password: "b".into(), path: String::new(), tls: false };
        let e = t.list().unwrap_err();
        assert!(e.starts_with(&format!("Cannot reach 127.0.0.1:{port}: ")), "{e}");

        let e = Ftp { host: " ".into(), port: 21, username: String::new(), password: String::new(), path: String::new(), tls: false }.list().unwrap_err();
        assert_eq!(e, "The FTP host is empty.");
    }

    #[test]
    fn a_server_that_does_not_do_tls_is_named() {
        let f = serve("secret", false, false);
        let mut t = ftp(&f, "secret", "");
        t.tls = true;
        let e = t.test().unwrap_err();
        assert!(e.contains("does not offer explicit FTPS (AUTH TLS answered: 500 AUTH not understood)"), "{e}");
    }

    #[test]
    fn a_server_that_refuses_passive_mode_gets_active_mode() {
        let f = serve("secret", true, false);
        let t = ftp(&f, "secret", "");
        let tmp = tempfile::tempdir().unwrap();
        let local = archive(tmp.path(), "cortendesk-backup-20260102-030000.tar", &[1u8; 300]);
        t.put(&local, "cortendesk-backup-20260102-030000.tar").unwrap();
        assert_eq!(t.list().unwrap(), vec![("cortendesk-backup-20260102-030000.tar".to_string(), Some(300))]);
        assert!(t.test().unwrap().ends_with("The server refused passive mode, so active mode is used."));
    }

    #[test]
    fn a_server_that_does_not_report_sizes_gives_none() {
        let f = serve("secret", false, true);
        let t = ftp(&f, "secret", "");
        let tmp = tempfile::tempdir().unwrap();
        let local = archive(tmp.path(), "cortendesk-backup-20260103-030000.tar", &[1u8; 30]);
        t.put(&local, "cortendesk-backup-20260103-030000.tar").unwrap();
        assert_eq!(t.list().unwrap(), vec![("cortendesk-backup-20260103-030000.tar".to_string(), None)]);
    }

    #[test]
    fn the_label_is_php_s() {
        let t = Ftp { host: " [::1] ".into(), port: 0, username: String::new(), password: String::new(), path: " /a/b/ ".into(), tls: true };
        assert_eq!(t.label(), "FTPS [::1]:21/a/b");
        let t = Ftp { host: "ftp.example.com".into(), port: 2121, username: String::new(), password: String::new(), path: String::new(), tls: false };
        assert_eq!(t.label(), "FTP ftp.example.com:2121");
    }

    #[test]
    fn passive_address_choice_and_replies() {
        // public and different: use the advertised one; private or equal: use the host entered
        assert!(use_pasv_address("8.8.8.8", "1.1.1.1"));
        assert!(!use_pasv_address("8.8.8.8", "8.8.8.8"));
        assert!(!use_pasv_address("192.168.1.5", "1.1.1.1"));
        assert!(!use_pasv_address("1.1.1.1", "10.0.0.2"));
        assert!(!use_pasv_address("100.64.0.1", "1.1.1.1"));
        assert_eq!(parse_pasv("227 Entering Passive Mode (10,0,0,5,195,80)."), Some((Ipv4Addr::new(10, 0, 0, 5), 50000)));
        assert_eq!(parse_pasv("227 nonsense"), None);
        assert_eq!(basenames(vec!["/a/b/x.tar".into(), "y.tar".into(), ".".into(), "..".into(), "dir/".into()]), vec!["x.tar", "y.tar", "dir"]);
        assert!(is_empty_dir_line("total 0") && is_empty_dir_line("drwxr-xr-x 2 u g 4096 Jan 1 00:00 .") && !is_empty_dir_line("-rw-r--r-- 1 u g 5 Jan 1 00:00 a.tar"));
        assert_eq!(failure("FTP delete of x failed", "550 No such file. ", ""), "FTP delete of x failed: 550 No such file.");
        assert_eq!(failure("a", "", "Hint."), "a. Hint.");
    }

    #[test]
    fn explicit_ftps_put_list_delete_and_test() {
        let f = serve_tls("secret");
        let mut t = ftp(&f, "secret", "backups");
        t.tls = true;
        let tmp = tempfile::tempdir().unwrap();
        let local = archive(tmp.path(), "cortendesk-backup-20260104-030000.tar", &[9u8; 70_000]);

        assert_eq!(t.list().unwrap(), vec![]);
        t.put(&local, "cortendesk-backup-20260104-030000.tar").unwrap();
        assert_eq!(f.fs.lock().unwrap().files["backups/cortendesk-backup-20260104-030000.tar"].len(), 70_000);
        assert_eq!(t.list().unwrap(), vec![("cortendesk-backup-20260104-030000.tar".to_string(), Some(70_000))]);

        let msg = t.test().unwrap();
        assert!(msg.starts_with("Connected to FTPS 127.0.0.1:") && msg.ends_with("Listing, upload and delete work."), "{msg}");
        t.delete("cortendesk-backup-20260104-030000.tar").unwrap();
        assert!(f.fs.lock().unwrap().files.is_empty());

        // a wrong password over TLS is still said plainly
        let mut bad = ftp(&f, "nope", "");
        bad.tls = true;
        assert_eq!(bad.test().unwrap_err(), "FTP login failed: Login incorrect.");
    }
}

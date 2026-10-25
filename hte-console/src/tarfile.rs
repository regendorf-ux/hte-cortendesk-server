//! Phase 6: the tar container of a backup archive, written and read by hand.
//!
//! PHP builds `cortendesk-backup-*.tar` with `PharData` (plain tar, no compression, no directory entries, entry names
//! like `db/users.ndjson.gz`). This module writes the same: ustar headers, regular files only, two zero blocks at the
//! end; and reads what PharData or GNU tar writes (ustar and v7 headers, pax `path`/`size` records, GNU long names;
//! directory entries and anything else are skipped). Reading is by name: the caller says which names it wants and
//! where each goes, so an entry's name is never used as a path.

use std::fs::File;
use std::io::{self, BufReader, Read, Write};
use std::path::Path;

const BLOCK: usize = 512;

fn octal(field: &mut [u8], value: u64) {
    // width-1 octal digits, zero padded, then NUL (what GNU tar and PharData write)
    let s = format!("{:0width$o}", value, width = field.len() - 1);
    let n = field.len() - 1;
    field[..n].copy_from_slice(s.as_bytes());
    field[n] = 0;
}

fn header(name: &str, size: u64, mode: u32, mtime: u64) -> io::Result<[u8; BLOCK]> {
    let mut h = [0u8; BLOCK];
    let (prefix, base) = split_name(name)?;
    h[..base.len()].copy_from_slice(base.as_bytes());
    octal(&mut h[100..108], mode as u64);
    octal(&mut h[108..116], 0);
    octal(&mut h[116..124], 0);
    if size >= 8u64.pow(11) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "entry too large for a tar header"));
    }
    octal(&mut h[124..136], size);
    octal(&mut h[136..148], mtime);
    h[148..156].copy_from_slice(b"        ");
    h[156] = b'0';
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    h[345..345 + prefix.len()].copy_from_slice(prefix.as_bytes());
    let sum: u32 = h.iter().map(|b| *b as u32).sum();
    let s = format!("{sum:06o}\0 ");
    h[148..156].copy_from_slice(s.as_bytes());
    Ok(h)
}

/// ustar splits a long name at a `/` into prefix (<= 155) and name (<= 100).
fn split_name(name: &str) -> io::Result<(&str, &str)> {
    if !name.is_ascii() || name.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "tar entry names are plain ASCII"));
    }
    if name.len() <= 100 {
        return Ok(("", name));
    }
    for (i, _) in name.match_indices('/') {
        let (p, b) = (&name[..i], &name[i + 1..]);
        if p.len() <= 155 && b.len() <= 100 && !b.is_empty() {
            return Ok((p, b));
        }
    }
    Err(io::Error::new(io::ErrorKind::InvalidInput, "tar entry name too long"))
}

pub struct Writer<W: Write> {
    w: W,
    mtime: u64,
}

impl<W: Write> Writer<W> {
    pub fn new(w: W, mtime: u64) -> Writer<W> {
        Writer { w, mtime }
    }

    /// One regular file read from `src`, `size` bytes (the file's current length).
    pub fn add_file(&mut self, name: &str, src: &Path, mode: u32) -> io::Result<()> {
        let mut f = File::open(src)?;
        let size = f.metadata()?.len();
        self.w.write_all(&header(name, size, mode, self.mtime)?)?;
        let copied = io::copy(&mut (&mut f).take(size), &mut self.w)?;
        if copied != size {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, format!("{} changed while it was being archived", src.display())));
        }
        self.pad(size)
    }

    pub fn add_bytes(&mut self, name: &str, data: &[u8], mode: u32) -> io::Result<()> {
        self.w.write_all(&header(name, data.len() as u64, mode, self.mtime)?)?;
        self.w.write_all(data)?;
        self.pad(data.len() as u64)
    }

    fn pad(&mut self, size: u64) -> io::Result<()> {
        let rem = (size % BLOCK as u64) as usize;
        if rem != 0 {
            self.w.write_all(&[0u8; BLOCK][..BLOCK - rem])?;
        }
        Ok(())
    }

    /// The end-of-archive blocks; returns the writer so the caller can sync it.
    pub fn finish(mut self) -> io::Result<W> {
        self.w.write_all(&[0u8; BLOCK * 2])?;
        self.w.flush()?;
        Ok(self.w)
    }
}

/// What the reader found, and the single reason it refused when it did.
#[derive(Debug)]
pub struct Bad(pub String);

impl From<io::Error> for Bad {
    fn from(e: io::Error) -> Bad {
        Bad(e.to_string())
    }
}

fn field_str(b: &[u8]) -> String {
    let end = b.iter().position(|c| *c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

fn field_num(b: &[u8]) -> Option<u64> {
    if b.first().map_or(false, |c| c & 0x80 != 0) {
        // GNU base-256
        let mut v: u64 = (b[0] & 0x7f) as u64;
        for c in &b[1..] {
            v = v.checked_mul(256)?.checked_add(*c as u64)?;
        }
        return Some(v);
    }
    let s: String = b.iter().take_while(|c| **c != 0).map(|c| *c as char).collect();
    let s = s.trim();
    if s.is_empty() {
        return Some(0);
    }
    u64::from_str_radix(s, 8).ok()
}

fn read_block<R: Read>(r: &mut R, buf: &mut [u8; BLOCK]) -> Result<bool, Bad> {
    let mut got = 0;
    while got < BLOCK {
        let n = r.read(&mut buf[got..])?;
        if n == 0 {
            break;
        }
        got += n;
    }
    match got {
        0 => Ok(false),
        BLOCK => Ok(true),
        _ => Err(Bad("the archive is cut short".into())),
    }
}

fn skip<R: Read>(r: &mut R, n: u64) -> Result<(), Bad> {
    let copied = io::copy(&mut r.take(n), &mut io::sink())?;
    if copied != n {
        return Err(Bad("the archive is cut short".into()));
    }
    Ok(())
}

fn padded(size: u64) -> u64 {
    size.div_ceil(BLOCK as u64) * BLOCK as u64
}

/// Walk a tar file. For every regular file `want(name)` is asked for a destination; `Some(path)` extracts the data
/// there (created fresh, mode 0600), `None` skips it. Returns the names extracted, in archive order. A later entry
/// of the same name replaces an earlier one (as tar does).
pub fn extract<F: FnMut(&str) -> Option<std::path::PathBuf>>(archive: &Path, mut want: F) -> Result<Vec<String>, Bad> {
    let mut r = BufReader::new(File::open(archive)?);
    let total = std::fs::metadata(archive).map(|m| m.len()).unwrap_or(u64::MAX);
    let mut out = vec![];
    let mut long_name: Option<String> = None;
    let mut pax_path: Option<String> = None;
    let mut pax_size: Option<u64> = None;
    let mut buf = [0u8; BLOCK];
    let mut zero_blocks = 0;
    loop {
        if !read_block(&mut r, &mut buf)? {
            // PHP writes the two end blocks too; an archive without them was cut off between two entries
            return Err(Bad("the archive is cut short (no end of archive)".into()));
        }
        if buf.iter().all(|b| *b == 0) {
            zero_blocks += 1;
            if zero_blocks >= 2 {
                break;
            }
            continue;
        }
        zero_blocks = 0;
        // checksum over the header with the checksum field read as spaces
        let stored = field_num(&buf[148..156]).ok_or_else(|| Bad("not a tar archive (bad checksum field)".into()))?;
        let sum: u64 = buf.iter().enumerate().map(|(i, b)| if (148..156).contains(&i) { 32u64 } else { *b as u64 }).sum();
        if sum != stored {
            return Err(Bad("not a tar archive (checksum mismatch)".into()));
        }
        let mut size = field_num(&buf[124..136]).ok_or_else(|| Bad("not a tar archive (bad size)".into()))?;
        if let Some(s) = pax_size.take() {
            size = s;
        }
        if size > total {
            return Err(Bad("the archive is cut short (an entry is larger than the file)".into()));
        }
        let kind = buf[156];
        match kind {
            b'x' | b'g' | b'L' => {
                if size > 1 << 20 {
                    return Err(Bad("an extended header is too large".into()));
                }
                let mut data = vec![0u8; size as usize];
                r.read_exact(&mut data).map_err(|_| Bad("the archive is cut short".into()))?;
                skip(&mut r, padded(size) - size)?;
                match kind {
                    b'L' => long_name = Some(field_str(&data)),
                    b'x' => {
                        // "<len> key=value\n" records
                        let mut rest = &data[..];
                        while !rest.is_empty() {
                            let sp = rest.iter().position(|c| *c == b' ').ok_or_else(|| Bad("bad pax record".into()))?;
                            let len: usize = std::str::from_utf8(&rest[..sp]).ok().and_then(|s| s.parse().ok()).ok_or_else(|| Bad("bad pax record".into()))?;
                            if len <= sp + 1 || len > rest.len() {
                                return Err(Bad("bad pax record".into()));
                            }
                            let rec = &rest[sp + 1..len - 1];
                            if let Some(eq) = rec.iter().position(|c| *c == b'=') {
                                let (k, v) = (&rec[..eq], &rec[eq + 1..]);
                                match k {
                                    b"path" => pax_path = Some(String::from_utf8_lossy(v).into_owned()),
                                    b"size" => pax_size = std::str::from_utf8(v).ok().and_then(|s| s.parse().ok()),
                                    _ => {}
                                }
                            }
                            rest = &rest[len..];
                        }
                    }
                    _ => {}
                }
            }
            b'0' | 0 | b'7' => {
                let name = match (pax_path.take(), long_name.take()) {
                    (Some(p), _) | (None, Some(p)) => p,
                    _ => {
                        let base = field_str(&buf[..100]);
                        let prefix = field_str(&buf[345..500]);
                        if prefix.is_empty() || &buf[257..262] != b"ustar" {
                            base
                        } else {
                            format!("{prefix}/{base}")
                        }
                    }
                };
                let name = name.trim_start_matches("./").to_string();
                match want(&name) {
                    Some(dest) => {
                        let mut f = create_private(&dest)?;
                        let copied = io::copy(&mut (&mut r).take(size), &mut f)?;
                        if copied != size {
                            return Err(Bad(format!("the archive is cut short inside {name}")));
                        }
                        f.sync_all()?;
                        skip(&mut r, padded(size) - size)?;
                        out.push(name);
                    }
                    None => skip(&mut r, padded(size))?,
                }
            }
            _ => {
                // directories, links, devices: nothing to extract
                long_name = None;
                pax_path = None;
                skip(&mut r, padded(size))?;
            }
        }
    }
    Ok(out)
}

fn create_private(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path)
}

/// The data of one named entry (small ones: the manifest).
pub fn read_entry(archive: &Path, name: &str, max: u64) -> Result<Option<Vec<u8>>, Bad> {
    let dir = tempdir_beside(archive)?;
    let dest = dir.join("entry");
    let found = extract(archive, |n| (n == name).then(|| dest.clone()));
    let res = match found {
        Ok(v) if v.is_empty() => Ok(None),
        Ok(_) => {
            let len = std::fs::metadata(&dest).map(|m| m.len()).unwrap_or(0);
            if len > max {
                Err(Bad(format!("{name} is larger than {max} bytes")))
            } else {
                std::fs::read(&dest).map(Some).map_err(Bad::from)
            }
        }
        Err(e) => Err(e),
    };
    let _ = std::fs::remove_dir_all(&dir);
    res
}

fn tempdir_beside(archive: &Path) -> Result<std::path::PathBuf, Bad> {
    // next to the archive, never in a shared /tmp
    let parent = archive.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
    let dir = parent.join(format!(".tar-{}", crate::laravel::str_random(10)));
    std::fs::create_dir(&dir)?;
    Ok(dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_then_read() {
        let d = tempfile::tempdir().unwrap();
        let tar = d.path().join("a.tar");
        let mut w = Writer::new(File::create(&tar).unwrap(), 1_700_000_000);
        w.add_bytes("manifest.json", b"{\"a\":1}", 0o644).unwrap();
        w.add_bytes("db/users.ndjson.gz", &vec![7u8; 1500], 0o644).unwrap();
        w.add_bytes("files/rustdesk/id_ed25519", b"", 0o644).unwrap();
        w.finish().unwrap();
        assert_eq!(std::fs::metadata(&tar).unwrap().len() % 512, 0);
        assert_eq!(read_entry(&tar, "manifest.json", 100).unwrap().unwrap(), b"{\"a\":1}");
        let out = d.path().join("o");
        std::fs::create_dir(&out).unwrap();
        let names = extract(&tar, |n| (n != "manifest.json").then(|| out.join(n.replace('/', "_")))).unwrap();
        assert_eq!(names, vec!["db/users.ndjson.gz", "files/rustdesk/id_ed25519"]);
        assert_eq!(std::fs::read(out.join("db_users.ndjson.gz")).unwrap(), vec![7u8; 1500]);
    }

    #[test]
    fn refuses_garbage_and_cut_archives() {
        let d = tempfile::tempdir().unwrap();
        let junk = d.path().join("j.tar");
        std::fs::write(&junk, vec![b'x'; 2048]).unwrap();
        assert!(extract(&junk, |_| None).is_err(), "not a tar");
        let tar = d.path().join("a.tar");
        let mut w = Writer::new(File::create(&tar).unwrap(), 1);
        w.add_bytes("db/a.ndjson.gz", &vec![1u8; 3000], 0o644).unwrap();
        w.finish().unwrap();
        let bytes = std::fs::read(&tar).unwrap();
        let cut = d.path().join("c.tar");
        std::fs::write(&cut, &bytes[..1200]).unwrap();
        assert!(extract(&cut, |_| Some(d.path().join("x"))).is_err(), "cut inside an entry");
        // a flipped byte in a header
        let mut bad = bytes.clone();
        bad[3] ^= 0xff;
        let b = d.path().join("b.tar");
        std::fs::write(&b, &bad).unwrap();
        assert!(extract(&b, |_| None).is_err(), "checksum");
    }

    #[test]
    fn long_names_split_at_a_slash() {
        let long = format!("{}/{}", "d".repeat(120), "f".repeat(50));
        let d = tempfile::tempdir().unwrap();
        let tar = d.path().join("a.tar");
        let mut w = Writer::new(File::create(&tar).unwrap(), 1);
        w.add_bytes(&long, b"x", 0o600).unwrap();
        w.finish().unwrap();
        let mut seen = vec![];
        extract(&tar, |n| {
            seen.push(n.to_string());
            None
        })
        .unwrap();
        assert_eq!(seen, vec![long]);
    }
}

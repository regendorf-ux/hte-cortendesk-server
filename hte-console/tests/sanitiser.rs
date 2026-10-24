//! The sanitiser's rules, one test each. Every value below is made up.

use hte_console::sanitise::{self, is_placeholder, Sanitiser};
use hte_console::fixture;
use serde_json::{json, Value};

fn s() -> Sanitiser {
    Sanitiser::new(Some("test-salt"), &["corp-internal.test".to_string(), "acme-hq".to_string()])
}

fn pair<'a>(path: &'a str, req: &'a [u8], resp: &'a [u8]) -> fixture::RawPair<'a> {
    fixture::RawPair {
        method: "POST",
        path,
        query: Some("id=123456789&v=1"),
        request_headers: vec![
            ("content-type".into(), "application/json".into()),
            ("authorization".into(), "Bearer abcdefghijklmnopqrstuvwxyz0123456789".into()),
            ("cookie".into(), "sess=SECRETVALUE; other=x".into()),
            ("host".into(), "console.corp-internal.test".into()),
            ("x-forwarded-for".into(), "203.0.113.77".into()),
            ("x-private".into(), "must-not-survive".into()),
        ],
        request_body: req,
        status: 200,
        response_headers: vec![
            ("content-type".into(), "application/json".into()),
            ("set-cookie".into(), "sess=NEWSECRET; Path=/; Domain=console.corp-internal.test".into()),
            ("x-powered-by".into(), "PHP".into()),
        ],
        response_body: resp,
    }
}

#[test]
fn same_value_same_placeholder_different_value_different() {
    let s = s();
    let a = s.placeholder(sanitise::Kind::DeviceId, "123456789");
    assert_eq!(a, s.placeholder(sanitise::Kind::DeviceId, "123456789"));
    assert_ne!(a, s.placeholder(sanitise::Kind::DeviceId, "123456780"));
    assert!(is_placeholder(&a));
    assert_eq!(s.placeholder(sanitise::Kind::User, "Alice"), s.placeholder(sanitise::Kind::User, "alice"));
}

#[test]
fn salt_decides_placeholders() {
    let other = Sanitiser::new(Some("another"), &[]);
    assert_ne!(s().placeholder(sanitise::Kind::Token, "x"), other.placeholder(sanitise::Kind::Token, "x"));
}

#[test]
fn json_by_key() {
    let s = s();
    let mut v = json!({
        "id": "123456789", "uuid": "AAAAAAAAAAAAAAAAAAAAAA==", "username": "jsmith", "hostname": "DESK-01",
        "email": "j@acme.example", "pk": "QUJD", "access_token": "short", "enable-keyboard": "Y", "version": "1.5.0",
        "conns": [1, 2], "nested": {"peer": "987654321", "password": ""}
    });
    s.json(&mut v, "");
    let t = v.to_string();
    for real in ["123456789", "jsmith", "DESK-01", "j@acme", "987654321", "\"short\"", "QUJD"] {
        assert!(!t.contains(real), "{real} survived: {t}");
    }
    assert_eq!(v["enable-keyboard"], "Y");
    assert_eq!(v["version"], "1.5.0");
    assert_eq!(v["conns"], json!([1, 2]));
    assert_eq!(v["nested"]["password"], "");
    assert!(s.leftovers(&v).is_empty());
}

#[test]
fn json_by_shape() {
    let s = s();
    let mut v = json!({"msg": "mail bob@corp-internal.test from 10.1.2.3 and fe80::1 via https://host.example.org:8443/x uuid 0b2f6a1e-1111-4222-8333-444455556666 jwt eyJhbGciOi.eyJzdWIiOiIx.c2ln and acme-HQ"});
    s.json(&mut v, "");
    let t = v.to_string();
    for real in ["bob", "10.1.2.3", "fe80", "host.example.org", "0b2f6a1e", "eyJhbGciOi", "acme-HQ", "corp-internal"] {
        assert!(!t.contains(real), "{real} survived: {t}");
    }
    assert!(t.contains(":8443/x"), "port and path are kept: {t}");
    assert!(s.leftovers(&v).is_empty());
}

#[test]
fn learned_ids_are_replaced_in_free_text_later_on() {
    let s = s();
    let mut a = json!({"id": "555666777"});
    s.learn_json(&a, "");
    s.json(&mut a, "");
    let mut b = json!({"log": "device 555666777 went offline", "other": "x555666777y"});
    s.json(&mut b, "");
    assert!(!b["log"].to_string().contains("555666777"), "{b}");
    assert!(b["other"] == "x555666777y", "no match inside a longer word");
}

#[test]
fn a_whole_pair_is_clean_and_keeps_relationships() {
    let s = s();
    let req = br#"{"id":"123456789","uuid":"AAAAAAAAAAAAAAAAAAAAAA==","ver":"1.5.0"}"#;
    let resp = br#"{"sysinfo":1,"note":"123456789 seen from 203.0.113.77"}"#;
    let v = fixture::build(&s, 1, &pair("/api/heartbeat", req, resp));
    let t = v.to_string();
    for real in [
        "123456789", "203.0.113.77", "corp-internal", "SECRETVALUE", "NEWSECRET", "abcdefghijklmnopqrstuvwxyz", "must-not-survive",
        "x-powered-by", "AAAAAAAAAAAAAAAAAAAAAA==",
    ] {
        assert!(!t.contains(real), "{real} survived: {t}");
    }
    assert!(s.leftovers(&v).is_empty(), "{:?}", s.leftovers(&v));
    // the id in the query string and the body is the same placeholder
    assert_eq!(v["query"]["id"], v["request"]["body"]["value"]["id"]);
    assert_eq!(v["request"]["cookies"]["other"].as_str().map(is_placeholder), Some(true));
    assert_eq!(v["response"]["status"], 200);
}

#[test]
fn pages_and_binaries_are_not_stored() {
    let s = s();
    let mut p = pair("/api/x", b"\x00\x01binary", b"<html>jsmith</html>");
    p.request_headers[0].1 = "application/octet-stream".into();
    p.response_headers[0].1 = "text/html".into();
    let v = fixture::build(&s, 2, &p);
    assert_eq!(v["request"]["body"]["kind"], "omitted");
    assert_eq!(v["response"]["body"]["kind"], "omitted");
    assert!(!v.to_string().contains("jsmith"));
}

#[test]
fn form_bodies_and_paths() {
    let s = s();
    let mut p = pair("/api/login/123456789/x", b"username=jsmith&password=hunter2hunter2&id=123456789", b"{}");
    p.request_headers[0].1 = "application/x-www-form-urlencoded".into();
    let v = fixture::build(&s, 3, &p);
    let t = v.to_string();
    for real in ["jsmith", "hunter2", "123456789"] {
        assert!(!t.contains(real), "{real} survived: {t}");
    }
    assert!(s.leftovers(&v).is_empty());
}

#[test]
fn scan_finds_leftovers_and_configured_literals() {
    let s = s();
    let dir = tempfile::tempdir().unwrap();
    let clean = fixture::build(&s, 1, &pair("/api/heartbeat", br#"{"id":"123456789"}"#, b"{}"));
    fixture::write(dir.path(), &clean, 1).unwrap();
    assert!(fixture::scan(&s, dir.path()).unwrap().is_empty());
    // a fixture that somebody edited by hand, or that an older version wrote
    let mut dirty: Value = clean.clone();
    dirty["request"]["body"]["value"]["id"] = json!("123456789");
    dirty["response"]["body"] = json!({"kind": "json", "value": {"msg": "see bob@elsewhere.org and acme-hq"}});
    fixture::write(dir.path(), &dirty, 2).unwrap();
    let found = fixture::scan(&s, dir.path()).unwrap();
    assert!(found.iter().any(|(_, p)| p.contains("not a placeholder")), "{found:?}");
    assert!(found.iter().any(|(_, p)| p.contains("configured literal")), "{found:?}");
    assert!(found.iter().all(|(f, _)| f.contains("000000000002") ), "only the edited file is flagged: {found:?}");
}

#[test]
fn sanitising_twice_changes_nothing() {
    let s = s();
    let v = fixture::build(&s, 9, &pair("/api/audit/conn", br#"{"from_peer":"111222333","peer":["444555666"],"ip":"198.51.100.4","ts":"2026-10-24T10:11:12Z","conn_id":5}"#, br#"{"data":"ok"}"#));
    assert!(s.leftovers(&v).is_empty());
    let mut again = v.clone();
    s.json(&mut again, "");
    assert_eq!(v, again);
}

#[test]
fn status_tokens_are_text_and_pages_are_not() {
    assert_eq!(fixture::status_token(b"SYSINFO_UPDATED"), Some("SYSINFO_UPDATED"));
    assert_eq!(fixture::status_token(b"ID_NOT_FOUND\n"), Some("ID_NOT_FOUND"));
    assert_eq!(fixture::status_token(b"jsmith"), None);
    assert_eq!(fixture::status_token(b"<html>OK</html>"), None);
    assert_eq!(fixture::status_token(b"OK"), None);
}

#[test]
fn the_synthetic_fixtures_are_clean() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/synthetic");
    let found = fixture::scan(&s(), &dir).unwrap();
    assert!(found.is_empty(), "{found:?}");
    assert!(fixture::list(&dir).unwrap().len() >= 8);
}

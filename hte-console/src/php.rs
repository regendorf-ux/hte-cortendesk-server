//! The previous console's value semantics, as far as the device endpoints need them (phase 1).
//!
//! The previous console is the specification, and its answers to odd input come from the previous console itself: `json_decode`,
//! `(string)` / `(int)` / `(bool)` casts, `base64_decode($s, true)`, `json_encode`. This module reproduces those
//! rules so the Rust handlers can be written line by line against the previous console's source. Strings are byte strings,
//! as in the previous console: a query value may be any bytes.
//!
//! Nothing here panics on input; every limit (nesting depth, variable count) is the previous console's own.

use std::collections::HashMap;

/// An array key after the previous console's normalisation: canonical decimal integer strings become integers.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Key {
    Int(i64),
    Str(Vec<u8>),
}

impl Key {
    pub fn from_bytes(b: &[u8]) -> Key {
        match canonical_int(b) {
            Some(i) => Key::Int(i),
            None => Key::Str(b.to_vec()),
        }
    }
    pub fn as_bytes(&self) -> Vec<u8> {
        match self {
            Key::Int(i) => i.to_string().into_bytes(),
            Key::Str(s) => s.clone(),
        }
    }
}

/// `"123"`, `"-5"`, `"0"` (not `"05"`, `"-0"`, `"+1"`, out of range): the previous console stores these as integer keys.
fn canonical_int(b: &[u8]) -> Option<i64> {
    let digits = b.strip_prefix(b"-").unwrap_or(b);
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) || (digits[0] == b'0' && digits.len() > 1) {
        return None;
    }
    if b == b"-0" {
        return None;
    }
    std::str::from_utf8(b).ok()?.parse::<i64>().ok()
}

/// An ordered the previous console array: insertion order, overwrite in place on a repeated key.
#[derive(Clone, Debug, Default)]
pub struct Arr {
    items: Vec<(Key, Val)>,
    index: HashMap<Key, usize>,
    next: i64,
}

impl Arr {
    pub fn new() -> Arr {
        Arr::default()
    }
    pub fn set(&mut self, k: Key, v: Val) {
        if let Key::Int(i) = k {
            if i >= self.next {
                self.next = i.saturating_add(1);
            }
        }
        match self.index.get(&k) {
            Some(&at) => self.items[at].1 = v,
            None => {
                self.index.insert(k.clone(), self.items.len());
                self.items.push((k, v));
            }
        }
    }
    /// `$a[] = $v`
    pub fn push(&mut self, v: Val) {
        let k = Key::Int(self.next);
        self.set(k, v);
    }
    pub fn get(&self, k: &Key) -> Option<&Val> {
        self.index.get(k).map(|&i| &self.items[i].1)
    }
    pub fn get_str(&self, k: &str) -> Option<&Val> {
        self.get(&Key::from_bytes(k.as_bytes()))
    }
    pub fn get_mut(&mut self, k: &Key) -> Option<&mut Val> {
        match self.index.get(k) {
            Some(&i) => Some(&mut self.items[i].1),
            None => None,
        }
    }
    pub fn contains(&self, k: &str) -> bool {
        self.get_str(k).is_some()
    }
    pub fn len(&self) -> usize {
        self.items.len()
    }
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
    pub fn iter(&self) -> impl Iterator<Item = &(Key, Val)> {
        self.items.iter()
    }
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut (Key, Val)> {
        self.items.iter_mut()
    }
    /// `$a + $b`: keys of `$a` win, keys only in `$b` are appended.
    pub fn union(mut self, other: &Arr) -> Arr {
        for (k, v) in other.iter() {
            if self.get(k).is_none() {
                self.set(k.clone(), v.clone());
            }
        }
        self
    }
}

impl PartialEq for Arr {
    /// The previous console's `===` on arrays: same pairs in the same order with identical values.
    fn eq(&self, other: &Arr) -> bool {
        self.items.len() == other.items.len() && self.items.iter().zip(other.items.iter()).all(|(a, b)| a.0 == b.0 && a.1 == b.1)
    }
}

/// A previous-console value.
#[derive(Clone, Debug)]
pub enum Val {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(Vec<u8>),
    Arr(Arr),
}

impl PartialEq for Val {
    /// The previous console's `===`.
    fn eq(&self, other: &Val) -> bool {
        match (self, other) {
            (Val::Null, Val::Null) => true,
            (Val::Bool(a), Val::Bool(b)) => a == b,
            (Val::Int(a), Val::Int(b)) => a == b,
            (Val::Float(a), Val::Float(b)) => a == b,
            (Val::Str(a), Val::Str(b)) => a == b,
            (Val::Arr(a), Val::Arr(b)) => a == b,
            _ => false,
        }
    }
}

/// What the previous console would throw. The handlers turn it into the answer the previous console's exception handler gives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fault {
    /// `(string) $array`: the previous console warns "Array to string conversion"; Laravel turns every warning into an ErrorException.
    ArrayToString,
    /// Anything else the previous console would throw (a database error, an invalid MAC, a bad key). The text is for our log only.
    Other(String),
}

impl Val {
    pub fn str(s: &str) -> Val {
        Val::Str(s.as_bytes().to_vec())
    }

    /// `(string) $v`
    pub fn to_php_string(&self) -> Result<Vec<u8>, Fault> {
        Ok(match self {
            Val::Null => vec![],
            Val::Bool(true) => b"1".to_vec(),
            Val::Bool(false) => vec![],
            Val::Int(i) => i.to_string().into_bytes(),
            Val::Float(f) => float_to_string(*f).into_bytes(),
            Val::Str(s) => s.clone(),
            Val::Arr(_) => return Err(Fault::ArrayToString),
        })
    }

    /// `(int) $v`
    pub fn to_int(&self) -> i64 {
        match self {
            Val::Null => 0,
            Val::Bool(b) => *b as i64,
            Val::Int(i) => *i,
            Val::Float(f) => dval_to_lval(*f),
            Val::Str(s) => str_to_int(s),
            Val::Arr(a) => !a.is_empty() as i64,
        }
    }

    /// `(bool) $v`
    pub fn to_bool(&self) -> bool {
        match self {
            Val::Null => false,
            Val::Bool(b) => *b,
            Val::Int(i) => *i != 0,
            Val::Float(f) => *f != 0.0,
            Val::Str(s) => !(s.is_empty() || s == b"0"),
            Val::Arr(a) => !a.is_empty(),
        }
    }

    /// `(array) $v`
    pub fn to_array(&self) -> Arr {
        match self {
            Val::Null => Arr::new(),
            Val::Arr(a) => a.clone(),
            other => {
                let mut a = Arr::new();
                a.push(other.clone());
                a
            }
        }
    }

    pub fn is_string(&self) -> bool {
        matches!(self, Val::Str(_))
    }

    /// `is_numeric($v)`
    pub fn is_numeric(&self) -> bool {
        match self {
            Val::Int(_) | Val::Float(_) => true,
            Val::Str(s) => is_numeric_str(s),
            _ => false,
        }
    }
}

// ------------------------------------------------------------------------------------------------ numbers ---

/// The previous console's runtime (7)+ `(int)` of a float: NaN and infinities are 0, out-of-range values wrap modulo 2^64.
pub fn dval_to_lval(d: f64) -> i64 {
    if !d.is_finite() {
        return 0;
    }
    if d >= -9.223372036854775808e18 && d < 9.223372036854775808e18 {
        return d as i64;
    }
    // zend_dval_to_lval_slow: modular arithmetic.
    let two64 = 18446744073709551616.0_f64;
    let mut dmod = d % two64;
    if dmod < 0.0 {
        // we're going to make this number positive; call ourselves recursively if the result is -zero
        dmod += two64;
        if dmod >= two64 {
            return 0;
        }
    }
    // `dmod > ZEND_LONG_MAX` compares against 2^63 as a double, so exactly 2^63 stays and C's cast
    // (cvttsd2si) yields i64::MIN, where Rust's `as` would saturate.
    if dmod > 9.223372036854775807e18 {
        dmod -= two64;
    }
    if dmod >= 9.223372036854775808e18 {
        return i64::MIN;
    }
    dmod as i64
}

/// `zend_dval_to_lval_cap`: saturating, used when a numeric string overflows.
fn dval_to_lval_cap(d: f64) -> i64 {
    if !d.is_finite() {
        return 0;
    }
    if d >= 9.223372036854775807e18 {
        i64::MAX
    } else if d <= -9.223372036854775808e18 {
        i64::MIN
    } else {
        d as i64
    }
}

fn is_ws(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)
}

/// The numeric prefix of a string as the previous console's `_is_numeric_string_ex` reads it.
/// Returns (value, consumed-up-to, is_float); None when there is no number at the start.
enum Num {
    Int(i64),
    Float(f64),
}

fn numeric_prefix(s: &[u8]) -> Option<(Num, usize)> {
    let mut i = 0;
    while i < s.len() && is_ws(s[i]) {
        i += 1;
    }
    let start = i;
    if i < s.len() && (s[i] == b'+' || s[i] == b'-') {
        i += 1;
    }
    let int_start = i;
    while i < s.len() && s[i].is_ascii_digit() {
        i += 1;
    }
    let int_digits = i - int_start;
    let mut frac_digits = 0;
    let mut is_float = false;
    if i < s.len() && s[i] == b'.' {
        let mut j = i + 1;
        while j < s.len() && s[j].is_ascii_digit() {
            j += 1;
        }
        frac_digits = j - i - 1;
        if int_digits + frac_digits > 0 {
            is_float = true;
            i = j;
        }
    }
    if int_digits + frac_digits == 0 {
        return None;
    }
    if i < s.len() && (s[i] == b'e' || s[i] == b'E') {
        let mut j = i + 1;
        if j < s.len() && (s[j] == b'+' || s[j] == b'-') {
            j += 1;
        }
        if j < s.len() && s[j].is_ascii_digit() {
            while j < s.len() && s[j].is_ascii_digit() {
                j += 1;
            }
            is_float = true;
            i = j;
        }
    }
    let text = std::str::from_utf8(&s[start..i]).ok()?;
    if !is_float {
        if let Ok(v) = text.parse::<i64>() {
            return Some((Num::Int(v), i));
        }
    }
    let f: f64 = text.parse().ok()?;
    Some((Num::Float(f), i))
}

/// `(int) "..."`: the leading number, 0 when there is none; overflowing or float-like strings saturate.
pub fn str_to_int(s: &[u8]) -> i64 {
    match numeric_prefix(s) {
        None => 0,
        Some((Num::Int(i), _)) => i,
        Some((Num::Float(f), _)) => dval_to_lval_cap(f),
    }
}

/// `is_numeric("...")`: the whole string is a number, leading and trailing whitespace allowed (the previous console's runtime (8)).
pub fn is_numeric_str(s: &[u8]) -> bool {
    match numeric_prefix(s) {
        None => false,
        Some((_, end)) => s[end..].iter().all(|&c| is_ws(c)),
    }
}

fn numeric_value(s: &[u8]) -> Option<f64> {
    match numeric_prefix(s)? {
        (Num::Int(i), end) if s[end..].iter().all(|&c| is_ws(c)) => Some(i as f64),
        (Num::Float(f), end) if s[end..].iter().all(|&c| is_ws(c)) => Some(f),
        _ => None,
    }
}

/// The previous console's runtime (8)'s comparison of two string array keys in `ksort` (SORT_REGULAR): numerically when both are numeric
/// strings, byte-wise otherwise.
pub fn smart_strcmp(a: &[u8], b: &[u8]) -> std::cmp::Ordering {
    if let (Some(x), Some(y)) = (numeric_value(a), numeric_value(b)) {
        if let Some(o) = x.partial_cmp(&y) {
            return o;
        }
    }
    a.cmp(b)
}

/// `ksort($a)` for an array whose keys are all strings or ints (the previous console's runtime (8): stable).
pub fn ksort(items: &mut [(Key, Val)]) {
    items.sort_by(|(a, _), (b, _)| match (a, b) {
        (Key::Int(x), Key::Int(y)) => x.cmp(y),
        (Key::Str(x), Key::Str(y)) => smart_strcmp(x, y),
        (Key::Int(x), Key::Str(y)) => int_str_cmp(*x, y),
        (Key::Str(x), Key::Int(y)) => int_str_cmp(*y, x).reverse(),
    });
}

fn int_str_cmp(i: i64, s: &[u8]) -> std::cmp::Ordering {
    match numeric_value(s) {
        Some(f) => (i as f64).partial_cmp(&f).unwrap_or(std::cmp::Ordering::Equal),
        None => i.to_string().as_bytes().cmp(s),
    }
}

/// `(string) $float` with the previous console's default `precision` of 14 (zend_gcvt).
pub fn float_to_string(f: f64) -> String {
    if f.is_nan() {
        return "NAN".into();
    }
    if f.is_infinite() {
        return if f > 0.0 { "INF".into() } else { "-INF".into() };
    }
    let neg = f.is_sign_negative();
    let a = f.abs();
    let (digits, decpt) = if a == 0.0 { ("0".to_string(), 1) } else { round_digits(a, 14) };
    let mut out = String::new();
    if neg {
        out.push('-');
    }
    let nd = 14;
    if if decpt < 0 { decpt < -3 } else { decpt > nd } {
        let mut e = decpt - 1;
        let esign = if e < 0 {
            e = -e;
            '-'
        } else {
            '+'
        };
        let mut chars = digits.chars();
        out.push(chars.next().unwrap_or('0'));
        out.push('.');
        let rest: String = chars.collect();
        if rest.is_empty() {
            out.push('0');
        } else {
            out.push_str(&rest);
        }
        out.push('E');
        out.push(esign);
        out.push_str(&e.to_string());
    } else if decpt < 0 {
        out.push_str("0.");
        for _ in 0..(-decpt) {
            out.push('0');
        }
        out.push_str(&digits);
    } else {
        let d = digits.as_bytes();
        for i in 0..decpt as usize {
            out.push(if i < d.len() { d[i] as char } else { '0' });
        }
        if (decpt as usize) < d.len() {
            if decpt == 0 {
                out.push('0');
            }
            out.push('.');
            out.push_str(&digits[decpt as usize..]);
        }
    }
    out
}

/// The shortest decimal digits of `a` (> 0) correctly rounded to at most `n` significant digits (ties to even),
/// trailing zeros removed, and the position of the decimal point (zend_dtoa mode 2).
fn round_digits(a: f64, n: usize) -> (String, i32) {
    // 40 digits are far more than a tie check needs; Rust's exponent formatting is exact.
    let s = format!("{:.40e}", a);
    let (mant, exp) = s.split_once('e').unwrap_or((&s, "0"));
    let mut exp: i32 = exp.parse().unwrap_or(0);
    let all: Vec<u8> = mant.bytes().filter(|c| c.is_ascii_digit()).collect();
    let (head, tail) = all.split_at(n.min(all.len()));
    let mut d: Vec<u8> = head.to_vec();
    let round_up = match tail.first() {
        Some(&c) if c > b'5' => true,
        Some(&b'5') => tail[1..].iter().any(|&c| c != b'0') || d.last().map_or(false, |&l| (l - b'0') % 2 == 1),
        _ => false,
    };
    if round_up {
        let mut i = d.len();
        loop {
            if i == 0 {
                d.insert(0, b'1');
                exp += 1;
                d.pop();
                break;
            }
            i -= 1;
            if d[i] == b'9' {
                d[i] = b'0';
            } else {
                d[i] += 1;
                break;
            }
        }
    }
    while d.len() > 1 && d.last() == Some(&b'0') {
        d.pop();
    }
    (String::from_utf8(d).unwrap_or_default(), exp + 1)
}

// ------------------------------------------------------------------------------------------- json_decode ---

pub struct JsonOpts {
    /// `JSON_BIGINT_AS_STRING`
    pub bigint_as_string: bool,
    /// The `$depth` argument (the previous console default 512).
    pub depth: usize,
}

impl Default for JsonOpts {
    fn default() -> Self {
        JsonOpts { bigint_as_string: false, depth: 512 }
    }
}

/// `json_decode($s, true)`: None where the previous console returns null because of an error.
pub fn json_decode(s: &[u8], opts: &JsonOpts) -> Option<Val> {
    // The previous console rejects invalid UTF-8 anywhere in the document.
    std::str::from_utf8(s).ok()?;
    let mut p = Parser { s, i: 0, opts, depth: 0 };
    p.ws();
    let v = p.value()?;
    p.ws();
    if p.i != s.len() {
        return None;
    }
    Some(v)
}

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
    opts: &'a JsonOpts,
    depth: usize,
}

impl Parser<'_> {
    fn ws(&mut self) {
        while self.i < self.s.len() && matches!(self.s[self.i], b' ' | b'\t' | b'\n' | b'\r') {
            self.i += 1;
        }
    }
    fn lit(&mut self, l: &[u8]) -> bool {
        if self.s[self.i..].starts_with(l) {
            self.i += l.len();
            true
        } else {
            false
        }
    }
    fn value(&mut self) -> Option<Val> {
        match *self.s.get(self.i)? {
            b'{' => self.object(),
            b'[' => self.array(),
            b'"' => self.string().map(Val::Str),
            b't' if self.lit(b"true") => Some(Val::Bool(true)),
            b'f' if self.lit(b"false") => Some(Val::Bool(false)),
            b'n' if self.lit(b"null") => Some(Val::Null),
            b'-' | b'0'..=b'9' => self.number(),
            _ => None,
        }
    }
    fn enter(&mut self) -> Option<()> {
        self.depth += 1;
        (self.depth <= self.opts.depth).then_some(())
    }
    fn object(&mut self) -> Option<Val> {
        self.enter()?;
        self.i += 1;
        let mut a = Arr::new();
        self.ws();
        if self.s.get(self.i) == Some(&b'}') {
            self.i += 1;
            self.depth -= 1;
            return Some(Val::Arr(a));
        }
        loop {
            self.ws();
            if self.s.get(self.i) != Some(&b'"') {
                return None;
            }
            let k = self.string()?;
            self.ws();
            if self.s.get(self.i) != Some(&b':') {
                return None;
            }
            self.i += 1;
            self.ws();
            let v = self.value()?;
            a.set(Key::from_bytes(&k), v);
            self.ws();
            match self.s.get(self.i) {
                Some(b',') => self.i += 1,
                Some(b'}') => {
                    self.i += 1;
                    break;
                }
                _ => return None,
            }
        }
        self.depth -= 1;
        Some(Val::Arr(a))
    }
    fn array(&mut self) -> Option<Val> {
        self.enter()?;
        self.i += 1;
        let mut a = Arr::new();
        self.ws();
        if self.s.get(self.i) == Some(&b']') {
            self.i += 1;
            self.depth -= 1;
            return Some(Val::Arr(a));
        }
        loop {
            self.ws();
            let v = self.value()?;
            a.push(v);
            self.ws();
            match self.s.get(self.i) {
                Some(b',') => self.i += 1,
                Some(b']') => {
                    self.i += 1;
                    break;
                }
                _ => return None,
            }
        }
        self.depth -= 1;
        Some(Val::Arr(a))
    }
    fn hex4(&mut self) -> Option<u32> {
        let h = self.s.get(self.i..self.i + 4)?;
        let v = u32::from_str_radix(std::str::from_utf8(h).ok()?, 16).ok()?;
        self.i += 4;
        Some(v)
    }
    fn string(&mut self) -> Option<Vec<u8>> {
        self.i += 1;
        let mut out = vec![];
        loop {
            let c = *self.s.get(self.i)?;
            self.i += 1;
            match c {
                b'"' => return Some(out),
                b'\\' => {
                    let e = *self.s.get(self.i)?;
                    self.i += 1;
                    match e {
                        b'"' => out.push(b'"'),
                        b'\\' => out.push(b'\\'),
                        b'/' => out.push(b'/'),
                        b'b' => out.push(8),
                        b'f' => out.push(12),
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'u' => {
                            let u = self.hex4()?;
                            let cp = if (0xD800..0xDC00).contains(&u) {
                                // a high surrogate must be followed by \u + a low one (else JSON_ERROR_UTF16)
                                if self.s.get(self.i..self.i + 2) != Some(b"\\u") {
                                    return None;
                                }
                                self.i += 2;
                                let lo = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&lo) {
                                    return None;
                                }
                                0x10000 + ((u - 0xD800) << 10) + (lo - 0xDC00)
                            } else if (0xDC00..0xE000).contains(&u) {
                                return None;
                            } else {
                                u
                            };
                            let ch = char::from_u32(cp)?;
                            let mut buf = [0u8; 4];
                            out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                        }
                        _ => return None,
                    }
                }
                0..=0x1f => return None,
                _ => out.push(c),
            }
        }
    }
    fn number(&mut self) -> Option<Val> {
        let start = self.i;
        if self.s[self.i] == b'-' {
            self.i += 1;
        }
        match self.s.get(self.i) {
            Some(b'0') => self.i += 1,
            Some(b'1'..=b'9') => {
                while self.s.get(self.i).map_or(false, u8::is_ascii_digit) {
                    self.i += 1;
                }
            }
            _ => return None,
        }
        let mut is_float = false;
        if self.s.get(self.i) == Some(&b'.') {
            self.i += 1;
            if !self.s.get(self.i).map_or(false, u8::is_ascii_digit) {
                return None;
            }
            while self.s.get(self.i).map_or(false, u8::is_ascii_digit) {
                self.i += 1;
            }
            is_float = true;
        }
        if matches!(self.s.get(self.i), Some(b'e') | Some(b'E')) {
            self.i += 1;
            if matches!(self.s.get(self.i), Some(b'+') | Some(b'-')) {
                self.i += 1;
            }
            if !self.s.get(self.i).map_or(false, u8::is_ascii_digit) {
                return None;
            }
            while self.s.get(self.i).map_or(false, u8::is_ascii_digit) {
                self.i += 1;
            }
            is_float = true;
        }
        let text = std::str::from_utf8(&self.s[start..self.i]).ok()?;
        if !is_float {
            if let Ok(i) = text.parse::<i64>() {
                return Some(Val::Int(i));
            }
            if self.opts.bigint_as_string {
                return Some(Val::str(text));
            }
        }
        text.parse::<f64>().ok().map(Val::Float)
    }
}

// ------------------------------------------------------------------------------------------- json_encode ---

/// `json_encode($v)` with the previous console's default flags (slashes and non-ASCII escaped). None where the previous console returns false
/// (invalid UTF-8, a non-finite float).
pub fn json_encode(v: &Val) -> Option<String> {
    let mut out = String::new();
    enc(v, &mut out)?;
    Some(out)
}

fn enc(v: &Val, out: &mut String) -> Option<()> {
    match v {
        Val::Null => out.push_str("null"),
        Val::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Val::Int(i) => out.push_str(&i.to_string()),
        Val::Float(f) => {
            if !f.is_finite() {
                return None;
            }
            // serialize_precision -1: the shortest repr, with ".0" kept for integral values.
            let s = format!("{:?}", f);
            out.push_str(&s.replace("e", "e+").replace("e+-", "e-"));
        }
        Val::Str(s) => enc_str(s, out)?,
        Val::Arr(a) => {
            let is_list = a.iter().enumerate().all(|(n, (k, _))| *k == Key::Int(n as i64));
            if is_list {
                out.push('[');
                for (n, (_, x)) in a.iter().enumerate() {
                    if n > 0 {
                        out.push(',');
                    }
                    enc(x, out)?;
                }
                out.push(']');
            } else {
                out.push('{');
                for (n, (k, x)) in a.iter().enumerate() {
                    if n > 0 {
                        out.push(',');
                    }
                    enc_str(&k.as_bytes(), out)?;
                    out.push(':');
                    enc(x, out)?;
                }
                out.push('}');
            }
        }
    }
    Some(())
}

/// A JSON string as the previous console writes it by default.
pub fn enc_str(s: &[u8], out: &mut String) -> Option<()> {
    let s = std::str::from_utf8(s).ok()?;
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '/' => out.push_str("\\/"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            // below 0x20 and beyond ASCII; DEL (0x7f) stays as it is in the previous console
            c if (c as u32) < 0x20 || (c as u32) > 0x7f => {
                let mut buf = [0u16; 2];
                for u in c.encode_utf16(&mut buf) {
                    out.push_str(&format!("\\u{:04x}", u));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
    Some(())
}

/// A previous-console array with string keys built from pairs (for responses and JSON columns).
pub fn assoc<I: IntoIterator<Item = (String, Val)>>(pairs: I) -> Val {
    let mut a = Arr::new();
    for (k, v) in pairs {
        a.set(Key::from_bytes(k.as_bytes()), v);
    }
    Val::Arr(a)
}

// ------------------------------------------------------------------------------------------- hash_equals ---

/// `hash_equals($known, $user)`: false at once on a length difference, else a compare whose time does not depend
/// on where the bytes differ.
pub fn hash_equals(known: &[u8], user: &[u8]) -> bool {
    if known.len() != user.len() {
        return false;
    }
    let diff = known.iter().zip(user).fold(0u8, |acc, (a, b)| acc | (a ^ b));
    std::hint::black_box(diff) == 0
}

// ------------------------------------------------------------------------------------------------ base64 ---

/// `base64_decode($s, true)`: whitespace is skipped, other foreign bytes fail, missing padding is accepted.
pub fn base64_decode_strict(s: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut i = 0usize;
    let mut padding = 0usize;
    let mut cur: u8 = 0;
    for &c in s {
        if c == b'=' {
            padding += 1;
            continue;
        }
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'\t' | b'\n' | b'\r' | b' ' => continue,
            _ => return None,
        };
        if padding > 0 {
            return None;
        }
        match i % 4 {
            0 => cur = v << 2,
            1 => {
                out.push(cur | (v >> 4));
                cur = (v & 0x0f) << 4;
            }
            2 => {
                out.push(cur | (v >> 2));
                cur = (v & 0x03) << 6;
            }
            _ => out.push(cur | v),
        }
        i += 1;
    }
    if i % 4 == 1 {
        return None;
    }
    if padding > 0 && (padding > 2 || (i + padding) % 4 != 0) {
        return None;
    }
    Some(out)
}

// -------------------------------------------------------------------------------------------- parse_str ---

/// `$_GET` / `$_POST` from a urlencoded string, as the previous console fills them: `a.b` and `a b` become `a_b`, `a[]=` and
/// `a[k]=` build arrays (at most 64 levels), at most 1000 variables (`max_input_vars`).
pub fn parse_str(s: &[u8]) -> Arr {
    let mut root = Arr::new();
    let mut count = 0;
    for part in s.split(|&c| c == b'&') {
        if part.is_empty() {
            continue;
        }
        count += 1;
        if count > 1000 {
            break;
        }
        let (k, v) = match part.iter().position(|&c| c == b'=') {
            Some(p) => (&part[..p], &part[p + 1..]),
            None => (part, &b""[..]),
        };
        let name = urldecode(k);
        let value = urldecode(v);
        register(&mut root, &name, value);
    }
    root
}

pub fn urldecode(s: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        match s[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < s.len() + 0 && i + 2 <= s.len() - 1 => {
                let h = |c: u8| (c as char).to_digit(16);
                match (h(s[i + 1]), h(s[i + 2])) {
                    (Some(a), Some(b)) => {
                        out.push((a * 16 + b) as u8);
                        i += 2;
                    }
                    _ => out.push(b'%'),
                }
            }
            c => out.push(c),
        }
        i += 1;
    }
    out
}

/// php_register_variable_ex, reduced to what a urlencoded string can express.
fn register(root: &mut Arr, raw: &[u8], value: Vec<u8>) {
    // The name stops at a NUL byte (the engine is not binary safe here); leading spaces are dropped.
    let raw = match raw.iter().position(|&c| c == 0) {
        Some(p) => &raw[..p],
        None => raw,
    };
    let raw: &[u8] = &raw[raw.iter().take_while(|&&c| c == b' ').count()..];
    let mut base = vec![];
    let mut i = 0;
    let mut is_array = false;
    while i < raw.len() {
        match raw[i] {
            b' ' | b'.' => base.push(b'_'),
            b'[' => {
                is_array = true;
                break;
            }
            c => base.push(c),
        }
        i += 1;
    }
    if base.is_empty() {
        return;
    }
    if !is_array {
        root.set(Key::from_bytes(&base), Val::Str(value));
        return;
    }
    // Collect the indices: "[a][]" -> [Some(a), None]. A "[" without its "]" turns into "_" and ends the name.
    let mut idx: Vec<Option<Vec<u8>>> = vec![];
    let rest = &raw[i..];
    let mut j = 0;
    while j < rest.len() && rest[j] == b'[' {
        match rest[j + 1..].iter().position(|&c| c == b']') {
            Some(close) => {
                let inner = &rest[j + 1..j + 1 + close];
                idx.push(if inner.is_empty() { None } else { Some(inner.to_vec()) });
                j = j + 1 + close + 1;
            }
            None => {
                if idx.is_empty() {
                    // "a[b" -> variable "a_b"
                    let mut name = base.clone();
                    name.push(b'_');
                    name.extend(rest[j + 1..].iter().map(|&c| if c == b' ' || c == b'.' { b'_' } else { c }));
                    root.set(Key::from_bytes(&name), Val::Str(value));
                    return;
                }
                break;
            }
        }
        if idx.len() > 64 {
            return;
        }
    }
    let mut slot = Key::from_bytes(&base);
    let mut cur: &mut Arr = root;
    for k in idx {
        let entry_is_arr = matches!(cur.get(&slot), Some(Val::Arr(_)));
        if !entry_is_arr {
            cur.set(slot.clone(), Val::Arr(Arr::new()));
        }
        let next = match cur.get_mut(&slot) {
            Some(Val::Arr(a)) => a,
            _ => return,
        };
        slot = match k {
            Some(k) => Key::from_bytes(&k),
            None => Key::Int(next.next),
        };
        cur = next;
    }
    cur.set(slot, Val::Str(value));
}

// ------------------------------------------------------------------------------------------------- trim ---

/// The previous console's `trim($s)` with the default characters " \t\n\r\0\x0B".
pub fn trim(s: &[u8]) -> &[u8] {
    let set = |c: &u8| matches!(*c, b' ' | b'\t' | b'\n' | b'\r' | 0 | 0x0b);
    let start = s.iter().position(|c| !set(c)).unwrap_or(s.len());
    let end = s.iter().rposition(|c| !set(c)).map_or(start, |e| e + 1);
    &s[start..end.max(start)]
}

const INVISIBLE: &[u32] = &[
    0x0009, 0x0020, 0x00A0, 0x00AD, 0x034F, 0x061C, 0x115F, 0x1160, 0x17B4, 0x17B5, 0x180E, 0x2000, 0x2001, 0x2002,
    0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008, 0x2009, 0x200A, 0x200B, 0x200C, 0x200D, 0x200E, 0x200F, 0x202F,
    0x205F, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0x2065, 0x206A, 0x206B, 0x206C, 0x206D, 0x206E, 0x206F, 0x3000,
    0x2800, 0x3164, 0xFEFF, 0xFFA0, 0x1D159, 0x1D173, 0x1D174, 0x1D175, 0x1D176, 0x1D177, 0x1D178, 0x1D179, 0x1D17A,
    0xE0020,
];

fn laravel_ws(c: char) -> bool {
    // PCRE `\s` under /u (UCP): the Unicode separators plus \t \n \v \f \r; not U+0085.
    (c.is_whitespace() && c != '\u{85}') || c == '\0' || INVISIBLE.contains(&(c as u32))
}

/// Laravel's `Str::trim` (the TrimStrings middleware): Unicode whitespace and invisible characters at both
/// ends. A string that is not valid UTF-8 makes `preg_replace` fail, and Laravel falls back to the previous console's `trim`.
pub fn laravel_trim(s: &[u8]) -> Vec<u8> {
    match std::str::from_utf8(s) {
        Ok(t) => t.trim_matches(laravel_ws).as_bytes().to_vec(),
        Err(_) => trim(s).to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn j(s: &str) -> Option<Val> {
        json_decode(s.as_bytes(), &JsonOpts::default())
    }

    #[test]
    fn json_decode_follows_php() {
        assert_eq!(j("9223372036854775807"), Some(Val::Int(i64::MAX)));
        assert_eq!(j("9223372036854775808"), Some(Val::Float(9223372036854775808.0)));
        let big = json_decode(b"18446744073709551615", &JsonOpts { bigint_as_string: true, depth: 512 });
        assert_eq!(big, Some(Val::str("18446744073709551615")));
        assert_eq!(j("-0"), Some(Val::Int(0)));
        assert_eq!(j("1.0"), Some(Val::Float(1.0)));
        assert_eq!(j("01"), None);
        assert_eq!(j("\"\\ud83d\\ude00\""), Some(Val::str("😀")));
        assert_eq!(j("\"\\ud83d\""), None);
        assert_eq!(j("\"a\u{1}\""), None);
        assert_eq!(j("[1,]"), None);
        assert_eq!(j(" {} "), Some(Val::Arr(Arr::new())));
        // keys: numeric strings become ints, a repeated key keeps its first position
        let v = j(r#"{"b":1,"5":2,"b":3}"#).unwrap();
        let Val::Arr(a) = v else { panic!() };
        let keys: Vec<Key> = a.iter().map(|(k, _)| k.clone()).collect();
        assert_eq!(keys, vec![Key::Str(b"b".to_vec()), Key::Int(5)]);
        assert_eq!(a.get_str("b"), Some(&Val::Int(3)));
        // depth: 512 levels decode, 513 do not
        let ok = "[".repeat(512) + &"]".repeat(512);
        let deep = "[".repeat(513) + &"]".repeat(513);
        assert!(j(&ok).is_some());
        assert!(j(&deep).is_none());
        assert_eq!(json_decode(b"\"\xff\"", &JsonOpts::default()), None);
    }

    #[test]
    fn casts_follow_php() {
        assert_eq!(Val::Float(1.0).to_php_string().unwrap(), b"1");
        assert_eq!(Val::Float(0.1 + 0.2).to_php_string().unwrap(), b"0.3");
        assert_eq!(float_to_string(1e15), "1.0E+15");
        assert_eq!(float_to_string(1e14), "1.0E+14");
        assert_eq!(float_to_string(1e13), "10000000000000");
        assert_eq!(float_to_string(123456789012345.0), "1.2345678901234E+14");
        assert_eq!(float_to_string(0.0001), "0.0001");
        assert_eq!(float_to_string(0.00001), "1.0E-5");
        assert_eq!(float_to_string(-0.0), "-0");
        assert_eq!(float_to_string(1.5e300), "1.5E+300");
        assert_eq!(float_to_string(f64::INFINITY), "INF");
        assert_eq!(Val::Bool(true).to_php_string().unwrap(), b"1");
        assert_eq!(Val::Arr(Arr::new()).to_php_string(), Err(Fault::ArrayToString));
        assert_eq!(Val::str(" 12abc").to_int(), 12);
        assert_eq!(Val::str("1e3").to_int(), 1000);
        assert_eq!(Val::str("99999999999999999999").to_int(), i64::MAX);
        assert_eq!(Val::str("abc").to_int(), 0);
        assert_eq!(Val::str(".5").to_int(), 0);
        assert_eq!(Val::Float(1e19).to_int(), dval_to_lval(1e19));
        assert_eq!(Val::Float(f64::NAN).to_int(), 0);
        assert_eq!(Val::Float(-1.9).to_int(), -1);
        assert!(!Val::str("0").to_bool());
        assert!(Val::str("0.0").to_bool());
        assert!(is_numeric_str(b" 1.5 "));
        assert!(!is_numeric_str(b"1.5x"));
        assert!(!is_numeric_str(b""));
    }

    #[test]
    fn dval_to_lval_wraps() {
        assert_eq!(dval_to_lval(18446744073709551616.0 + 4096.0), 4096);
        assert_eq!(dval_to_lval(9223372036854775808.0), i64::MIN);
    }

    #[test]
    fn hash_equals_as_php() {
        assert!(hash_equals(b"", b""));
        assert!(hash_equals(b"abc", b"abc"));
        assert!(!hash_equals(b"abc", b"abd"));
        assert!(!hash_equals(b"abc", b"abcd"));
        assert!(!hash_equals(b"abc", b""));
    }

    #[test]
    fn base64_strict() {
        assert_eq!(base64_decode_strict(b"YWJj"), Some(b"abc".to_vec()));
        assert_eq!(base64_decode_strict(b"YQ"), Some(b"a".to_vec()));
        assert_eq!(base64_decode_strict(b"YQ=="), Some(b"a".to_vec()));
        assert_eq!(base64_decode_strict(b"Y Q = ="), Some(b"a".to_vec()));
        assert_eq!(base64_decode_strict(b"Y"), None);
        assert_eq!(base64_decode_strict(b"YQ=a"), None);
        assert_eq!(base64_decode_strict(b"YQ==="), None);
        assert_eq!(base64_decode_strict(b"Y!Q="), None);
    }

    #[test]
    fn json_encode_like_php() {
        let v = assoc(vec![("a/b".to_string(), Val::str("é\"\u{1}")), ("n".to_string(), Val::Int(3))]);
        assert_eq!(json_encode(&v).unwrap(), r#"{"a\/b":"\u00e9\"\u0001","n":3}"#);
        assert_eq!(json_encode(&Val::Arr(Arr::new())).unwrap(), "[]");
        assert_eq!(json_encode(&Val::str("😀")).unwrap(), r#""\ud83d\ude00""#);
        assert_eq!(json_encode(&Val::Str(vec![0xff])), None);
        assert_eq!(json_encode(&Val::str("a\u{7f}b\u{80}")).unwrap(), "\"a\u{7f}b\\u0080\"");
    }

    #[test]
    fn parse_str_like_php() {
        let a = parse_str(b"a.b=1&c[]=x&c[]=y&d[k][]=z&e[=w&%20f=v&id=1&id=2");
        assert_eq!(a.get_str("a_b"), Some(&Val::str("1")));
        let Some(Val::Arr(c)) = a.get_str("c") else { panic!() };
        assert_eq!(c.len(), 2);
        assert!(matches!(a.get_str("d"), Some(Val::Arr(_))));
        assert_eq!(a.get_str("e_"), Some(&Val::str("w")));
        assert_eq!(a.get_str("f"), Some(&Val::str("v")));
        assert_eq!(a.get_str("id"), Some(&Val::str("2")));
        assert_eq!(parse_str(b"x=%zz%41").get_str("x"), Some(&Val::str("%zzA")));
    }

    #[test]
    fn trims() {
        assert_eq!(laravel_trim(" \u{200B}a b\u{FEFF}\n".as_bytes()), b"a b");
        assert_eq!(laravel_trim(b" \xffa "), b"\xffa");
        assert_eq!(trim(b"\0 x \x0b"), b"x");
        assert_eq!(trim(b"   "), b"");
    }

    #[test]
    fn ksort_regular() {
        let mut v = vec![(Key::Str(b"b".to_vec()), Val::Null), (Key::Str(b"a".to_vec()), Val::Null), (Key::Str(b"10".to_vec()), Val::Null), (Key::Str(b"9.5".to_vec()), Val::Null)];
        ksort(&mut v);
        let keys: Vec<Vec<u8>> = v.iter().map(|(k, _)| k.as_bytes()).collect();
        assert_eq!(keys, vec![b"9.5".to_vec(), b"10".to_vec(), b"a".to_vec(), b"b".to_vec()]);
    }
}

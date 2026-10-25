//! Carbon's wording of time, as the console's views print it (`diffForHumans()`, `diffForHumans(short: true)`,
//! `shortAbsoluteDiffForHumans($other, 2)`), read from Carbon 3 as shipped in the PHP image (CarbonInterval::forHumans,
//! the `en` language file). The app runs in UTC, so every time is a Unix second.
//!
//! The calendar part is PHP's `DateTime::diff` (years, months, days, hours, minutes, seconds, borrowing days from the
//! month before the later date); Carbon then names the first non-zero unit (parts = 1: truncated, never rounded), a
//! week being `d / 7`. A zero difference reads "1 second ago" (Carbon's default `NO_ZERO_DIFF`).

use chrono::{DateTime, Datelike, Timelike, Utc};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Interval {
    y: i64,
    m: i64,
    d: i64,
    h: i64,
    i: i64,
    s: i64,
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ => {
            if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 {
                29
            } else {
                28
            }
        }
    }
}

/// `$earlier->diff($later)` (both UTC, `earlier <= later`).
fn diff(earlier: i64, later: i64) -> Interval {
    let a = DateTime::<Utc>::from_timestamp(earlier, 0).unwrap_or_default();
    let b = DateTime::<Utc>::from_timestamp(later, 0).unwrap_or_default();
    let mut r = Interval {
        y: b.year() as i64 - a.year() as i64,
        m: b.month() as i64 - a.month() as i64,
        d: b.day() as i64 - a.day() as i64,
        h: b.hour() as i64 - a.hour() as i64,
        i: b.minute() as i64 - a.minute() as i64,
        s: b.second() as i64 - a.second() as i64,
    };
    if r.s < 0 {
        r.s += 60;
        r.i -= 1;
    }
    if r.i < 0 {
        r.i += 60;
        r.h -= 1;
    }
    if r.h < 0 {
        r.h += 24;
        r.d -= 1;
    }
    let (mut year, mut month) = (b.year() as i64, b.month() as i64);
    while r.d < 0 {
        r.m -= 1;
        month -= 1;
        if month < 1 {
            month += 12;
            year -= 1;
        }
        r.d += days_in_month(year, month);
    }
    while r.m < 0 {
        r.m += 12;
        r.y -= 1;
    }
    r
}

const UNITS: [(&str, &str, &str); 7] = [
    // long name, short form for one, short form for several
    ("year", "yr", "yrs"),
    ("month", "mo", "mos"),
    ("week", "w", "w"),
    ("day", "d", "d"),
    ("hour", "h", "h"),
    ("minute", "m", "m"),
    ("second", "s", "s"),
];

fn parts_of(iv: &Interval) -> [i64; 7] {
    [iv.y, iv.m, iv.d / 7, iv.d % 7, iv.h, iv.i, iv.s]
}

fn label(unit: usize, count: i64, short: bool) -> String {
    let (long, one, many) = UNITS[unit];
    if short {
        format!("{count}{}", if count == 1 { one } else { many })
    } else {
        format!("{count} {long}{}", if count == 1 { "" } else { "s" })
    }
}

/// `$time->diffForHumans()` / `diffForHumans(short: true)`: "5 minutes ago", "2h ago"; "from now" for a time ahead.
pub fn ago(then: i64, now: i64, short: bool) -> String {
    let future = then > now;
    let (a, b) = if future { (now, then) } else { (then, now) };
    let p = parts_of(&diff(a, b));
    let text = match p.iter().position(|v| *v > 0) {
        Some(u) => label(u, p[u], short),
        None => label(6, 1, short),
    };
    format!("{text} {}", if future { "from now" } else { "ago" })
}

/// `$later->shortAbsoluteDiffForHumans($earlier, 2)`: "1h 5m", "3m 12s", at most two non-zero units.
pub fn short_absolute(later: i64, earlier: i64) -> String {
    let (a, b) = if later < earlier { (later, earlier) } else { (earlier, later) };
    let p = parts_of(&diff(a, b));
    let mut out: Vec<String> = vec![];
    for (u, v) in p.iter().enumerate() {
        if *v > 0 {
            out.push(label(u, *v, true));
        }
        if out.len() >= 2 {
            break;
        }
    }
    if out.is_empty() {
        out.push(label(6, 1, true));
    }
    out.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: i64 = 1_760_000_000; // 2025-10-09 08:53:20 UTC

    #[test]
    fn the_first_unit_only_and_truncated() {
        assert_eq!(ago(T - 5, T, false), "5 seconds ago");
        assert_eq!(ago(T - 1, T, false), "1 second ago");
        assert_eq!(ago(T, T, false), "1 second ago");
        assert_eq!(ago(T - 125, T, false), "2 minutes ago");
        assert_eq!(ago(T - 3 * 3600 - 1800, T, false), "3 hours ago");
        assert_eq!(ago(T - 86400, T, false), "1 day ago");
        assert_eq!(ago(T - 10 * 86400, T, false), "1 week ago");
        assert_eq!(ago(T - 20 * 86400, T, false), "2 weeks ago");
        assert_eq!(ago(T - 400 * 86400, T, false), "1 year ago");
    }

    #[test]
    fn short_forms() {
        assert_eq!(ago(T - 125, T, true), "2m ago");
        assert_eq!(ago(T - 7200, T, true), "2h ago");
        assert_eq!(ago(T - 3 * 86400, T, true), "3d ago");
        assert_eq!(ago(T - 14 * 86400, T, true), "2w ago");
        assert_eq!(ago(T - 400 * 86400, T, true), "1yr ago");
        assert_eq!(ago(T - 800 * 86400, T, true), "2yrs ago");
    }

    #[test]
    fn months_come_from_the_calendar() {
        // 2025-10-09 back to 2025-08-20: 1 month 20 days (borrowing September's 30 days)
        let then = DateTime::parse_from_rfc3339("2025-08-20T08:53:20Z").unwrap().timestamp();
        assert_eq!(ago(then, T, false), "1 month ago");
        let then = DateTime::parse_from_rfc3339("2025-05-09T08:53:20Z").unwrap().timestamp();
        assert_eq!(ago(then, T, true), "5mos ago");
    }

    #[test]
    fn the_future_reads_from_now() {
        assert_eq!(ago(T + 90, T, false), "1 minute from now");
    }

    #[test]
    fn durations_keep_two_units() {
        assert_eq!(short_absolute(T + 3600 + 300, T), "1h 5m");
        assert_eq!(short_absolute(T + 3600 + 5, T), "1h 5s");
        assert_eq!(short_absolute(T + 200, T), "3m 20s");
        assert_eq!(short_absolute(T + 2 * 86400 + 3 * 3600 + 4 * 60, T), "2d 3h");
        assert_eq!(short_absolute(T, T), "1s");
    }
}

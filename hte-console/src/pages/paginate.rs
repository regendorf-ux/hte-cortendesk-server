//! `LengthAwarePaginator` and `UrlWindow` (3 pages on each side), as Livewire's bootstrap pagination view lays them out.

use serde::Serialize;

#[derive(Serialize, Debug, PartialEq, Eq)]
#[serde(untagged)]
pub enum Element {
    /// The "..." between windows.
    Gap(String),
    Pages(Vec<i64>),
}

#[derive(Serialize, Debug)]
pub struct Page {
    pub current: i64,
    pub per_page: i64,
    pub total: i64,
    pub last: i64,
    pub has_pages: bool,
    pub on_first: bool,
    pub has_more: bool,
    /// `firstItem()` / `lastItem()`: None (printed as 0 by the view) for an empty page.
    pub first_item: i64,
    pub last_item: i64,
    pub elements: Vec<Element>,
}

const ON_EACH_SIDE: i64 = 3;

fn range(a: i64, b: i64) -> Vec<i64> {
    (a..=b).collect()
}

/// `UrlWindow::get()`.
fn window(current: i64, last: i64) -> Vec<Element> {
    let side = ON_EACH_SIDE;
    if last < side * 2 + 8 {
        return vec![Element::Pages(range(1, last))];
    }
    let win = side + 4;
    let start = || Element::Pages(range(1, 2));
    let finish = || Element::Pages(range(last - 1, last));
    let gap = || Element::Gap("...".into());
    if current <= win {
        return vec![Element::Pages(range(1, win + side)), gap(), finish()];
    }
    if current > last - win {
        return vec![start(), gap(), Element::Pages(range(last - (win + (side - 1)), last))];
    }
    vec![start(), gap(), Element::Pages(range(current - side, current + side)), gap(), finish()]
}

/// `$query->paginate($perPage)` for `total` rows at page `current` (the page is not clamped: a page past the end is
/// simply empty, as in Laravel).
pub fn page(current: i64, per_page: i64, total: i64, shown: i64) -> Page {
    let last = std::cmp::max((total + per_page - 1) / per_page, 1);
    let has_pages = last > 1;
    let (first_item, last_item) = if shown > 0 { ((current - 1) * per_page + 1, (current - 1) * per_page + shown) } else { (0, 0) };
    Page {
        current,
        per_page,
        total,
        last,
        has_pages,
        on_first: current <= 1,
        has_more: current < last,
        first_item,
        last_item,
        elements: if has_pages { window(current, last) } else { vec![] },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_lists_show_every_page() {
        let p = page(1, 20, 45, 20);
        assert_eq!((p.last, p.has_pages, p.first_item, p.last_item, p.has_more), (3, true, 1, 20, true));
        assert_eq!(p.elements, vec![Element::Pages(vec![1, 2, 3])]);
        let p = page(3, 20, 45, 5);
        assert_eq!((p.first_item, p.last_item, p.has_more), (41, 45, false));
        assert!(!page(1, 20, 20, 20).has_pages);
        let e = page(1, 20, 0, 0);
        assert_eq!((e.first_item, e.last_item, e.last), (0, 0, 1));
    }

    #[test]
    fn long_lists_slide() {
        // 30 pages: near the start, in the middle, near the end
        let p = page(2, 10, 300, 10);
        assert_eq!(p.elements, vec![Element::Pages(range(1, 10)), Element::Gap("...".into()), Element::Pages(vec![29, 30])]);
        let p = page(15, 10, 300, 10);
        assert_eq!(
            p.elements,
            vec![Element::Pages(vec![1, 2]), Element::Gap("...".into()), Element::Pages(range(12, 18)), Element::Gap("...".into()), Element::Pages(vec![29, 30])]
        );
        let p = page(29, 10, 300, 10);
        assert_eq!(p.elements, vec![Element::Pages(vec![1, 2]), Element::Gap("...".into()), Element::Pages(range(21, 30))]);
    }

    #[test]
    fn a_page_past_the_end_is_empty_not_clamped() {
        let p = page(9, 20, 45, 0);
        assert_eq!((p.current, p.first_item, p.last_item, p.has_more), (9, 0, 0, false));
    }
}

/* The console pages served by hte-console: what Livewire did in the browser, with htmx and plain forms. */
(function () {
    'use strict';

    // htmx: every request carries the page's CSRF token (the forms also carry `_token`); a 422 (validation errors) is
    // swapped in like a page, as Livewire redrew the component with its messages.
    if (window.htmx) {
        window.htmx.config.responseHandling = [
            { code: '204', swap: false },
            { code: '[23]..', swap: true },
            { code: '422', swap: true, error: false },
            { code: '[45]..', swap: false, error: true },
            { code: '...', swap: false }
        ];
        document.body.addEventListener('htmx:configRequest', function (event) {
            var meta = document.querySelector('meta[name="csrf-token"]');
            if (meta) {
                event.detail.headers['X-CSRF-TOKEN'] = meta.getAttribute('content');
            }
        });
    }

    // The "saved" alerts went away on their own after four seconds (wire:poll.4s).
    function autohide(root) {
        var alerts = (root || document).querySelectorAll('[data-rd-autohide]');
        Array.prototype.forEach.call(alerts, function (el) {
            if (el.getAttribute('data-rd-armed')) {
                return;
            }
            el.setAttribute('data-rd-armed', '1');
            window.setTimeout(function () {
                if (el.parentNode) {
                    el.parentNode.removeChild(el);
                }
            }, parseInt(el.getAttribute('data-rd-autohide'), 10) || 4000);
        });
    }
    document.addEventListener('DOMContentLoaded', function () { autohide(document); });
    document.body.addEventListener('htmx:afterSwap', function (event) { autohide(event.target); });

    // "Export CSV": the current filter bar, as a download (the list under it may be a keystroke behind).
    document.addEventListener('click', function (event) {
        var button = event.target.closest ? event.target.closest('[data-rd-export]') : null;
        if (!button) {
            return;
        }
        var form = button.closest('form');
        var params = new URLSearchParams();
        if (form) {
            new FormData(form).forEach(function (value, key) {
                if (value !== '' && key !== 'perPage') {
                    params.append(key, value);
                }
            });
        }
        var query = params.toString();
        window.location.href = button.getAttribute('data-rd-export') + (query ? '?' + query : '');
    });

    // My Account: the theme is saved as soon as it is picked and applied to the open page.
    document.addEventListener('change', function (event) {
        var radio = event.target;
        if (!radio.matches || !radio.matches('[data-rd-theme-radio]') || !window.fetch) {
            return;
        }
        var meta = document.querySelector('meta[name="csrf-token"]');
        window.fetch('/account/theme', {
            method: 'POST',
            credentials: 'same-origin',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'X-CSRF-TOKEN': meta ? meta.getAttribute('content') : ''
            },
            body: JSON.stringify({ theme: radio.value })
        }).then(function (response) {
            if (response.ok) {
                window.dispatchEvent(new CustomEvent('rd-theme', { detail: { theme: radio.value } }));
            }
        });
    });

    // wire:confirm: a button or link that asks first.
    document.addEventListener('click', function (event) {
        var el = event.target.closest ? event.target.closest('[data-rd-confirm]') : null;
        if (el && !window.confirm(el.getAttribute('data-rd-confirm'))) {
            event.preventDefault();
            event.stopPropagation();
        }
    }, true);

    // wire:model.live on a select or a ticked box: the form it belongs to is sent as soon as it changes.
    document.addEventListener('change', function (event) {
        var el = event.target;
        if (el.matches && el.matches('[data-rd-autosubmit-select], [data-rd-autosubmit-box]') && el.form) {
            if (el.form.requestSubmit) { el.form.requestSubmit(); } else { el.form.submit(); }
        }
    });

    // The device list's bulk bar: shown while rows are ticked, with the count; "Clear" and the header box clear / tick the page.
    function boxes() { return document.querySelectorAll('[data-rd-rowbox]'); }
    function refreshBulk() {
        var slot = document.getElementById('bulk-slot');
        var tpl = document.getElementById('bulk-bar');
        if (!slot || !tpl) { return; }
        var ticked = {};
        var n = 0;
        Array.prototype.forEach.call(boxes(), function (b) { if (b.checked && !ticked[b.value]) { ticked[b.value] = 1; n++; } });
        var shown = slot.getAttribute('data-rd-shown') === '1';
        if (n > 0 && !shown) {
            slot.innerHTML = tpl.innerHTML;
            slot.setAttribute('data-rd-shown', '1');
        } else if (n === 0 && shown) {
            slot.innerHTML = '';
            slot.removeAttribute('data-rd-shown');
        }
        var count = slot.querySelector('[data-rd-selcount]');
        if (count) { count.textContent = String(n); }
        // the same device has a box in the table and in the card list: keep the pair in step
        Array.prototype.forEach.call(document.querySelectorAll('[data-rd-selectall]'), function (all) {
            var list = boxes();
            var every = list.length > 0;
            Array.prototype.forEach.call(list, function (b) { if (!b.checked) { every = false; } });
            all.checked = every;
        });
    }
    document.addEventListener('change', function (event) {
        var el = event.target;
        if (!el.matches) { return; }
        if (el.matches('[data-rd-selectall]')) {
            Array.prototype.forEach.call(boxes(), function (b) { b.checked = el.checked; });
            refreshBulk();
        } else if (el.matches('[data-rd-rowbox]')) {
            Array.prototype.forEach.call(boxes(), function (b) { if (b !== el && b.value === el.value) { b.checked = el.checked; } });
            refreshBulk();
        }
    });
    document.addEventListener('click', function (event) {
        var clear = event.target.closest ? event.target.closest('[data-rd-clearsel]') : null;
        if (clear) {
            event.preventDefault();
            Array.prototype.forEach.call(boxes(), function (b) { b.checked = false; });
            refreshBulk();
        }
    });
    if (document.body) { document.body.addEventListener('htmx:afterSwap', refreshBulk); }

    // A select that decides which other fields apply (the sharing rule's "Share with"): show those, disable the rest.
    document.addEventListener('change', function (event) {
        var sel = event.target;
        if (!sel.matches || !sel.matches('[data-rd-switch]') || !sel.form) { return; }
        Array.prototype.forEach.call(sel.form.querySelectorAll('[data-rd-when]'), function (box) {
            var on = box.getAttribute('data-rd-when') === sel.value;
            box.classList.toggle('d-none', !on);
            Array.prototype.forEach.call(box.querySelectorAll('select, input'), function (f) { f.disabled = !on; });
        });
    });

    // Escape closes the open dialog (wire:keydown.escape).
    document.addEventListener('keydown', function (event) {
        if (event.key !== 'Escape') { return; }
        var close = document.querySelector('.modal [data-rd-close]');
        if (close) { close.click(); }
    });
})();

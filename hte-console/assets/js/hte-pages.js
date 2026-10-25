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
})();

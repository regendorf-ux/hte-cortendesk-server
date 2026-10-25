/**
 * CortenDesk front-end helpers. Plain script, no build step.
 */
(function () {
    'use strict';

    /**
     * Copy text to the clipboard and confirm it on the button.
     *
     * navigator.clipboard only exists in a secure context — HTTPS or
     * localhost — so on a plain-HTTP LAN install, which is a documented way to
     * run this, calling it directly throws and the button silently does
     * nothing. The execCommand path is deprecated but works on any origin, so
     * it covers exactly the case the modern API refuses.
     */
    function copyText(text) {
        if (navigator.clipboard && window.isSecureContext) {
            return navigator.clipboard.writeText(text);
        }

        return new Promise(function (resolve, reject) {
            var field = document.createElement('textarea');
            field.value = text;
            // Off-screen rather than hidden: execCommand needs a real
            // selection, and display:none cannot hold one.
            field.setAttribute('readonly', '');
            field.style.position = 'fixed';
            field.style.top = '-1000px';
            field.style.opacity = '0';
            document.body.appendChild(field);

            try {
                field.select();
                field.setSelectionRange(0, field.value.length);
                document.execCommand('copy') ? resolve() : reject(new Error('Copy was refused'));
            } catch (error) {
                reject(error);
            } finally {
                document.body.removeChild(field);
            }
        });
    }

    /**
     * Copy `text`, then say so on `button` for a moment.
     *
     * Silent success is its own problem: without feedback nobody knows whether
     * the click registered, and they click again.
     */
    window.rdCopy = function (text, button) {
        copyText(text).then(
            function () { flash(button, 'ri-check-line', 'Copied'); },
            function () { flash(button, 'ri-error-warning-line', 'Press Ctrl+C to copy'); }
        );
    };

    /** Copy the value of the input immediately before the button. */
    window.rdCopyPrevious = function (button) {
        window.rdCopy(button.previousElementSibling.value, button);
    };

    function flash(button, icon, label) {
        if (!button) {
            return;
        }

        var mark = button.querySelector('i');
        var original = mark ? mark.className : null;

        button.setAttribute('aria-label', label);
        button.setAttribute('title', label);

        if (mark) {
            mark.className = icon + (original && original.indexOf('me-1') !== -1 ? ' me-1' : '');
        }

        window.setTimeout(function () {
            button.removeAttribute('aria-label');
            if (mark && original !== null) {
                mark.className = original;
            }
        }, 1500);
    }
})();

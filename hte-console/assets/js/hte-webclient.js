// HTE Remote's web client: hands the bundle its configuration (window.__RD__) and, for a signed-in person, connects to a
// computer in their own HTE Remote address book without asking for a password, as the desktop client does. The password box
// stays, collapsed, for a computer outside the book or a manual override. The bundle itself is not changed: this fills the
// box it already reads and presses its Connect button. A password is never logged and never kept past that click.
(function () {
    "use strict";
    var holder = document.getElementById("rd-config");
    var cfg = {};
    try { cfg = JSON.parse(holder.getAttribute("data-config") || "{}"); } catch (e) { cfg = {}; }
    window.__RD__ = cfg;
    holder.removeAttribute("data-config");
    if (!cfg.hteCredentialUrl) { return; }

    var manual = false;      // the person opened the box themself: what they type wins
    var passThrough = false; // our own re-click
    var usedManaged = false;
    var el = {};

    function fetchCredential(id) {
        return fetch(cfg.hteCredentialUrl, {
            method: "POST",
            credentials: "same-origin",
            cache: "no-store",
            headers: { "Content-Type": "application/x-www-form-urlencoded", "X-CSRF-TOKEN": cfg.hteCsrf || "", "Accept": "application/json" },
            body: "id=" + encodeURIComponent(id)
        }).then(function (r) { return r.ok ? r.json() : null; }).then(function (j) { return j && j.password ? String(j.password) : ""; }).catch(function () { return ""; });
    }

    function expand(note) {
        el.box.classList.remove("hte-collapsed");
        el.row.classList.remove("hte-collapsed-row");
        el.save.classList.remove("hte-hidden");
        el.toggle.hidden = true;
        manual = true;
        if (note) { el.help.textContent = note; }
        el.pw.focus();
    }

    function currentId() {
        var typed = el.peer && el.peer.value ? el.peer.value : (cfg.peerId || "");
        return String(typed).replace(/\s+/g, "");
    }

    function onConnect(ev) {
        if (passThrough || manual || el.pw.value) { return; }
        var id = currentId();
        if (!id) { return; }
        ev.stopImmediatePropagation();
        ev.preventDefault();
        el.btn.disabled = true;
        fetchCredential(id).then(function (pw) {
            el.btn.disabled = false;
            if (!pw) {
                expand("No password is kept for this computer. Enter its password.");
                return;
            }
            usedManaged = true;
            el.pw.value = pw;
            el.save.querySelector("input").checked = false;
            passThrough = true;
            try { el.btn.click(); } finally { passThrough = false; }
        });
    }

    function onEnter(ev) {
        if (ev.key === "Enter") { onConnect(ev); }
    }

    function setup() {
        el.pw = document.getElementById("rd-password");
        el.btn = document.getElementById("rd-connect");
        el.peer = document.getElementById("rd-peer-id");
        if (!el.pw || !el.btn) { return false; }
        el.box = el.pw.closest(".rd-input");
        el.row = el.pw.closest(".rd-connect-row");
        el.save = document.querySelector(".rd-save");
        el.help = document.querySelector(".rd-help");
        el.box.classList.add("hte-collapsed");
        el.row.classList.add("hte-collapsed-row");
        el.save.classList.add("hte-hidden");
        el.help.textContent = "You are signed in. A computer in your HTE Remote book connects without a password.";
        el.toggle = document.createElement("button");
        el.toggle.type = "button";
        el.toggle.className = "hte-pw-toggle";
        el.toggle.textContent = "Use a different password";
        el.toggle.addEventListener("click", function () { expand(); });
        el.row.insertAdjacentElement("afterend", el.toggle);
        el.btn.addEventListener("click", onConnect, true);
        el.peer.addEventListener("keydown", onEnter, true);
        // a failed login with the kept password: show the box so the person can type another
        var err = document.getElementById("rd-overlay-error");
        if (err) {
            new MutationObserver(function () { if (!err.hidden && usedManaged) { usedManaged = false; expand(); } }).observe(err, { attributes: true, attributeFilter: ["hidden"] });
        }
        // opened with ?id=: connect at once unless the bundle already started (a hash it kept on this device)
        if (cfg.peerId) {
            setTimeout(function () { if (!el.btn.disabled) { el.btn.click(); } }, 150);
        }
        return true;
    }

    var tries = 0;
    (function wait() {
        if (setup()) { return; }
        if (++tries < 200) { setTimeout(wait, 50); }
    })();
})();

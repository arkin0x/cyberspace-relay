// Create Speakeasy, the browser side, shared by the region page (/C/<hex>)
// and the landing page (/speakeasy): ask for an invoice, then follow one
// order to its end, reading it exactly as docs/speakeasies.md states it.
// No DOM here: each page draws the states its own way, so both read an
// order the same way and neither can show a refund owed as a success.
(function () {
  "use strict";
  function remember(key, id) {
    try { if (id) localStorage.setItem(key, id); else localStorage.removeItem(key); } catch (e) {}
  }
  function remembered(key) {
    try { return localStorage.getItem(key); } catch (e) { return null; }
  }
  // create sends POST endpoint {"region", "name"?} and resolves
  // {ok, status, o}: the order, or {"error"} when refused.
  function create(endpoint, body) {
    return fetch(endpoint, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) })
      .then(function (r) {
        return r.json().catch(function () { return {}; }).then(function (o) { return { ok: r.ok, status: r.status, o: o }; });
      });
  }
  // outcome names how a finished order ended, or "" while it runs:
  //   made               paid, and the speakeasy is open (o.url)
  //   made-without-name  open, but its name was taken first: the name's
  //                      part is owed back
  //   owed               paid, but it bought nothing: owed back, or held
  //   expired            the invoice expired unpaid
  //   unknown            the wallet never answered about it
  function outcome(o) {
    if (o.applied && o.url && !o.needs_owner) return "made";
    if (o.applied && o.url) return "made-without-name";
    if (o.applied) return "owed";
    if (o.status === "expired") return "expired";
    if (o.status === "unknown") return "unknown";
    return "";
  }
  // watch polls GET endpoint/<id>: h.update(o) on every answer, h.paid(o)
  // while it is paid but not yet applied, then once h.end(outcome, o), or
  // h.gone() when the relay no longer knows the order. A failed request is
  // tried again. It returns a function that stops it.
  function watch(endpoint, id, h) {
    var stopped = false, timer = null;
    function again(ms) { if (!stopped) timer = setTimeout(tick, ms); }
    function tick() {
      fetch(endpoint + "/" + encodeURIComponent(id), { cache: "no-store" })
        .then(function (r) { if (r.status === 404) throw "gone"; return r.json(); })
        .then(function (o) {
          if (stopped) return;
          if (h.update) h.update(o);
          var end = outcome(o);
          if (end) { h.end(end, o); return; }
          if (o.status === "paid" && h.paid) h.paid(o);
          again(3000);
        })
        .catch(function (e) {
          if (stopped) return;
          if (e === "gone") { if (h.gone) h.gone(); return; }
          again(6000);
        });
    }
    tick();
    return function () { stopped = true; clearTimeout(timer); };
  }
  window.SpeakeasyOrder = { create: create, watch: watch, outcome: outcome, remember: remember, remembered: remembered };
})();

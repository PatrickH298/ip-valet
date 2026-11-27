// Keeps the states of the person's registrations current while workers
// apply them: as long as any is still being applied (or removed), it asks
// /status every few seconds and updates the page in place. It stops once
// none is, after five minutes, or at the first error, such as an ended
// session. Without it, reloading the page shows the same.
(function () {
  "use strict";
  if (!window.fetch) {
    return;
  }
  var settling = ["pending", "removing"];
  var started = Date.now();
  var rows = function () {
    return Array.prototype.slice.call(document.querySelectorAll("li[data-entry]"));
  };
  var waiting = function () {
    return rows().some(function (li) {
      return settling.indexOf(li.getAttribute("data-state")) >= 0;
    });
  };
  var update = function (entries) {
    var byID = {};
    entries.forEach(function (e) {
      byID[e.id] = e;
    });
    rows().forEach(function (li) {
      var e = byID[li.getAttribute("data-entry")];
      if (!e) {
        return;
      }
      li.setAttribute("data-state", e.state);
      var badge = li.querySelector(".badge");
      if (badge) {
        badge.className = "badge state-" + e.state;
        badge.textContent = e.label;
      }
      var detail = li.querySelector(".detail");
      if (detail) {
        detail.textContent = e.detail || "";
      }
    });
  };
  var poll = function () {
    if (!waiting() || Date.now() - started > 5 * 60 * 1000) {
      return;
    }
    fetch("/status", { credentials: "same-origin", cache: "no-store", headers: { Accept: "application/json" } })
      .then(function (r) {
        if (!r.ok || r.redirected) {
          throw new Error("status " + r.status);
        }
        return r.json();
      })
      .then(function (d) {
        update(d.entries || []);
        setTimeout(poll, 3000);
      })
      .catch(function () {});
  };
  setTimeout(poll, 2000);
})();

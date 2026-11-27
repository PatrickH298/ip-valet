// Fills in the address this page's own connection cannot show: for each
// address family the server could not see, it asks a host reachable over
// that family only. The host answers with the address it saw and a signed
// proof, which the register form sends back, so the server registers only
// addresses it saw itself. Without this script the page still registers
// the address of its own connection.
(function () {
  "use strict";
  var form = document.getElementById("register");
  if (!form || !window.fetch || !window.URL) {
    return;
  }
  var token = form.getAttribute("data-detect-token");
  var rows = form.querySelectorAll(".addr-row[data-detect-url]");
  Array.prototype.forEach.call(rows, function (row) {
    var out = row.querySelector(".addr");
    var select = row.querySelector("select");
    var url;
    try {
      url = new URL(row.getAttribute("data-detect-url"));
    } catch (e) {
      return;
    }
    url.searchParams.set("t", token);
    row.setAttribute("data-state", "detecting");
    out.textContent = "Detecting…";
    var fail = function () {
      row.setAttribute("data-state", "none");
      out.textContent = "Not detected";
    };
    var timer = setTimeout(fail, 10000);
    fetch(url.toString(), { mode: "cors", credentials: "omit", cache: "no-store" })
      .then(function (r) {
        if (!r.ok) {
          throw new Error("status " + r.status);
        }
        return r.json();
      })
      .then(function (d) {
        clearTimeout(timer);
        // A host that answers over the other family is set up wrong:
        // its address belongs to the other row, which already has one.
        if (!d.address || !d.proof || d.family !== row.getAttribute("data-family")) {
          fail();
          return;
        }
        row.setAttribute("data-state", "detected");
        out.textContent = d.address;
        if (select) {
          select.disabled = false;
        }
        var proof = document.createElement("input");
        proof.type = "hidden";
        proof.name = "proof";
        proof.value = d.proof;
        form.appendChild(proof);
      })
      .catch(function () {
        clearTimeout(timer);
        fail();
      });
  });
})();

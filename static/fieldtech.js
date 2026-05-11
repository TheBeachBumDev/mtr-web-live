// v1.0.7-hotfix6
(function () {
  "use strict";

  function $(id) { return document.getElementById(id); }

  function setStatus(msg) {
    var el = $("statusText");
    if (el) el.textContent = msg || "";
  }

  function setHint(msg) {
    var el = $("passwordHint");
    if (el) el.textContent = msg || "";
  }

  function normalizeIp(val) {
    if (val === null || val === undefined) return null;
    if (typeof val === "string") return val;
    if (typeof val === "object") {
      if (val.ip) return String(val.ip);
      if (val.address) return String(val.address);
      if (val.value) return String(val.value);
    }
    return String(val);
  }

  function setOut(id, val) {
    var el = $(id);
    if (el) el.textContent = (val === null || val === undefined) ? "—" : String(val);
  }

  async function copyText(text) {
    try {
      await navigator.clipboard.writeText(text);
      setStatus("Copied.");
      setTimeout(function () { setStatus(""); }, 1200);
    } catch (e) {
      setStatus("Copy failed.");
      setTimeout(function () { setStatus(""); }, 1500);
    }
  }

  function clearAll() {
    // Customer
    setOut("outCustomerId", "—");
    setOut("outCustomerName", "—");
    setOut("outPppoeUser", "—");
    setOut("outPppoePass", "—");
    setHint("");
    setStatus("");

    // IPAM
    setAntennaIp(null);
    setOut("outNextIp", "—");
    setOut("outNextNet", "—");
    setOut("ipamMsg", "—");

    var dd = $("ipamLocation");
    if (dd) dd.innerHTML = "";
  }

  function setAntennaIp(ipVal, meta) {
    var ip = normalizeIp(ipVal);
    setOut("outAntennaIp", ip || "—");
    var area = $("ipamAssignArea");
    if (!area) return;

    if (ip) {
      area.style.display = "none";
      var extra = "";
      try {
        if (meta && typeof meta === "object") {
          var loc = meta.location_name ? String(meta.location_name) : "";
          var cidr = meta.network_cidr ? String(meta.network_cidr) : "";
          if (loc || cidr) extra = " (" + [loc, cidr].filter(Boolean).join(" • ") + ")";
        }
      } catch (e) {}
      setOut("outAntennaIpHint", "This customer already has an antenna IP linked locally." + extra);
    } else {
      area.style.display = "block";
      setOut("outAntennaIpHint", "If empty, select a Location and click Assign IP to allocate the next free IP (gateway .1 reserved)." );
    }
  }

  async function ipamLoadLocations() {
    var dd = $("ipamLocation");
    if (!dd) return;

    dd.innerHTML = "";
    try {
      var r = await fetch("/api/ipam/locations", { credentials: "same-origin" });
      if (!r.ok) throw new Error("HTTP " + r.status);
      var data = await r.json();

      if (!data || !data.ok || !data.locations || !data.locations.length) {
        var o = document.createElement("option");
        o.value = "";
        o.textContent = "No locations (open /ipam to add)";
        dd.appendChild(o);
        return;
      }

            var added = 0;
      data.locations.forEach(function (l) {
        if (!l) return;
        var id = (l.id !== undefined && l.id !== null) ? l.id : "";
        var name = (l.name !== undefined && l.name !== null) ? String(l.name) : "";
        if (!id || !name) return;
        var o = document.createElement("option");
        o.value = id;
        o.textContent = name;
        dd.appendChild(o);
        added++;
      });
      if (!added) {
        var o = document.createElement("option");
        o.value = "";
        o.textContent = "No valid locations found";
        dd.appendChild(o);
      }
    } catch (e) {
      var o = document.createElement("option");
      o.value = "";
      o.textContent = "Location load error";
      dd.appendChild(o);
    }
  }

  async function ipamRefreshNext() {
    setOut("ipamMsg", "Loading...");
    var dd = $("ipamLocation");
    var lid = dd ? dd.value : "";

    if (!lid) {
      setOut("outNextIp", "—");
      setOut("outNextNet", "—");
      setOut("ipamMsg", "No location selected.");
      return;
    }

    try {
      var r = await fetch("/api/ipam/next?location_id=" + encodeURIComponent(lid), { credentials: "same-origin" });
      var data = await r.json();

      if (!data || !data.ok) {
        setOut("outNextIp", "—");
        setOut("outNextNet", "—");
        setOut("ipamMsg", "Error: " + (data && data.detail ? data.detail : "Unable to fetch next IP"));
        return;
      }

      setOut("outNextIp", data.ip || "—");
      setOut("outNextNet", data.network_cidr ? ("Network: " + data.network_cidr) : "—");
      setOut("ipamMsg", data.ip ? "Ready." : "No free IP found for this location.");
    } catch (e) {
      setOut("ipamMsg", "Error: " + (e && e.message ? e.message : String(e)));
    }
  }

  async function ipamUse(customerId) {
    setOut("ipamMsg", "Assigning...");
    var dd = $("ipamLocation");
    var lid = dd ? dd.value : "";

    if (!lid) {
      setOut("ipamMsg", "No location selected.");
      return;
    }

    try {
      var r = await fetch("/api/ipam/use", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ customer_id: customerId, location_id: lid })
      });
      var data = await r.json();

      if (!data || !data.ok) {
        setOut("ipamMsg", "Error: " + (data && data.detail ? data.detail : "Unable to assign IP"));
        return;
      }

      var ip = data.result && data.result.ip ? data.result.ip : null;
      setAntennaIp(ip);
      setOut("ipamMsg", data.result && data.result.already_assigned ? "Already assigned." : "Assigned.");
    } catch (e) {
      setOut("ipamMsg", "Error: " + (e && e.message ? e.message : String(e)));
    }
  }

  async function lookup() {
    var id = parseInt(($("customerId") && $("customerId").value) || "", 10);
    if (!id || id <= 0) {
      setStatus("Enter a valid Customer ID.");
      return;
    }

    setStatus("Looking up...");
    setHint("");

    try {
      var resp = await fetch("/api/fieldtech/customer/" + encodeURIComponent(id), { credentials: "same-origin" });
      var data = await resp.json().catch(function () { return null; });

      if (!resp.ok || !data || !data.ok) {
        var msg = (data && (data.detail || data.message)) ? (data.detail || data.message) : ("HTTP " + resp.status);
        throw new Error(msg);
      }

      setOut("outCustomerId", data.customer_id);
      setOut("outCustomerName", data.customer_name || "");
      setOut("outPppoeUser", data.pppoe_username || "—");

      if (data.password_available && data.pppoe_password) {
        setOut("outPppoePass", data.pppoe_password);
        setHint("");
      } else {
        setOut("outPppoePass", "Not available");
        setHint("Note: Splynx often does not return PPPoE passwords via API unless explicitly allowed for the API user/key.");
      }

      // Local IPAM link (customer -> antenna IP)
      setAntennaIp(data.antenna_ip || null, data.antenna_ip || null);

      var _linkedIp = normalizeIp(data.antenna_ip);
      if (!_linkedIp) {
        await ipamLoadLocations();
        await ipamRefreshNext();
      }

      setStatus("Done.");
      setTimeout(function () { setStatus(""); }, 1500);
    } catch (e) {
      clearAll();
      setStatus("Error: " + (e && e.message ? e.message : String(e)));
    }
  }

  function wire() {
    var lookupBtn = $("lookupBtn");
    var clearBtn = $("clearBtn");
    var input = $("customerId");
    var dd = $("ipamLocation");

    if (lookupBtn) lookupBtn.addEventListener("click", lookup);
    if (clearBtn) clearBtn.addEventListener("click", clearAll);
    if (input) input.addEventListener("keydown", function (ev) {
      if (ev.key === "Enter") lookup();
    });

    if (dd) dd.addEventListener("change", function () {
      ipamRefreshNext();
    });

    document.addEventListener("click", function (ev) {
      var t = ev.target;

      if (t && t.id === "btnIpamRefresh") {
        ipamRefreshNext();
        return;
      }

      if (t && t.id === "btnUseIp") {
        var cid = parseInt(($("customerId") && $("customerId").value) || "", 10);
        if (!cid) { setOut("ipamMsg", "Lookup a customer first."); return; }
        ipamUse(cid);
        return;
      }

      if (!t) return;
      var copyFrom = t.getAttribute && t.getAttribute("data-copy");
      if (!copyFrom) return;

      var el = $(copyFrom);
      var text = el ? (el.textContent || "") : "";
      if (!text || text === "—" || text === "Not available") {
        setStatus("Nothing to copy.");
        return;
      }
      copyText(text);
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", wire);
  } else {
    wire();
  }
})();

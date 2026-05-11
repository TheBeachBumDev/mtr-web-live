// v1.0.4-hotfix-pdf9
// v1.0.4-hotfix-pdf4
// Client-side PDF exporter:
// - Keeps index.html stable (only a single include line)
// - Sends destination hop time-series to backend
// - Backend generates a 1-page management PDF (latency + loss) via ReportLab
(function () {
  "use strict";

  function setErr(msg) {
    try { if (typeof setError === "function") setError(msg || ""); } catch (e) {}
  }

  function mean(arr) {
    if (!arr || !arr.length) return null;
    var s = 0;
    for (var i = 0; i < arr.length; i++) s += Number(arr[i] || 0);
    return s / arr.length;
  }

  function maxv(arr) {
    if (!arr || !arr.length) return null;
    var m = -Infinity;
    for (var i = 0; i < arr.length; i++) {
      var v = Number(arr[i]);
      if (isFinite(v) && v > m) m = v;
    }
    return isFinite(m) ? m : null;
  }

  async function downloadBlob(filename, blob) {
    var url = URL.createObjectURL(blob);
    var a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(function () { try { URL.revokeObjectURL(url); } catch (e) {} }, 2000);
  }

  window.exportPDF = async function exportPDF() {
    setErr("");

    try {
      if (typeof lastSnapshot === "undefined" || !lastSnapshot || !Array.isArray(lastSnapshot.hops) || lastSnapshot.hops.length === 0) {
        setErr("No data yet. Start a test and wait for hops to appear, then export.");
        return;
      }

      var dst = lastSnapshot.hops[lastSnapshot.hops.length - 1];
      if (!dst) {
        setErr("No destination hop yet. Let it run a bit longer, then export.");
        return;
      }

      var hopKey = String(dst.hop);
      var st = (typeof hopCharts !== "undefined" && hopCharts && hopCharts.get) ? hopCharts.get(hopKey) : null;

      // Prefer post-warmup series if available
      var latSeries = (st && Array.isArray(st.latData) && st.latData.length) ? st.latData.slice() : [];
      var lossSeries = (st && Array.isArray(st.lossData) && st.lossData.length) ? st.lossData.slice() : [];

      var avgLat = latSeries.length ? mean(latSeries) : (typeof dst.avg === "number" ? dst.avg : null);
      var avgLoss = lossSeries.length ? mean(lossSeries) : (typeof dst.loss === "number" ? dst.loss : null);
      var worstLat = latSeries.length ? maxv(latSeries) : (typeof dst.worst === "number" ? dst.worst : null);

      var targetEl = document.getElementById("target");
      var freqEl = document.getElementById("freq");
      var target = (targetEl && targetEl.value ? String(targetEl.value) : "").trim();
      var freq = (freqEl && freqEl.value ? String(freqEl.value) : "1.0").trim();

      var payload = {
        generated_iso: new Date().toISOString(),
        user: (typeof USERNAME !== "undefined" && USERNAME) ? USERNAME : "",
        target: target,
        freq_s: parseFloat(freq || "1.0"),
        destination_ip: dst.ip || "",
        avg_latency_ms: avgLat,
        worst_latency_ms: worstLat,
        avg_loss_pct: avgLoss,
        samples: latSeries.length || 0,
        latency_series_ms: latSeries,
        loss_series_pct: lossSeries
      };

      var res = await fetch("/api/pdf_summary", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });

      if (!res.ok) {
        var t = "";
        try { t = await res.text(); } catch (e) {}
        setErr("PDF export failed (" + res.status + "). " + (t || ""));
        return;
      }

      var blob = await res.blob();
      var safeTarget = (target || "mtr").replace(/[^a-zA-Z0-9._-]+/g, "_");
      var filename = "MTR_Summary_" + safeTarget + ".pdf";
      await downloadBlob(filename, blob);
    } catch (e) {
      setErr("PDF export failed: " + (e && e.message ? e.message : e));
    }
  };
})();

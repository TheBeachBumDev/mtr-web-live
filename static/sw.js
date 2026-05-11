/* Service worker: Web Push → native notifications (works when browser is closed/minimized). */
self.addEventListener("push", function (event) {
  let payload = { title: "Monitoring", body: "", tag: "mtr-monitor" };
  try {
    if (event.data) {
      var j = event.data.json();
      if (j && typeof j === "object") payload = Object.assign(payload, j);
    }
  } catch (e) {
    try {
      var t = event.data ? event.data.text() : "";
      if (t) payload.body = t;
    } catch (e2) {}
  }
  /* requireInteraction: keeps banner visible until dismissed on many desktops (Windows respects this where supported). */
  event.waitUntil(
    self.registration.showNotification(payload.title || "Monitoring", {
      body: payload.body || "",
      tag: payload.tag || "mtr-monitor",
      renotify: true,
      requireInteraction: payload.requireInteraction !== false,
      data: { url: payload.url || "/monitoring" },
    })
  );
});

self.addEventListener("notificationclick", function (event) {
  event.notification.close();
  var targetUrl = "/";
  try {
    var d = event.notification && event.notification.data;
    if (d && d.url) targetUrl = String(d.url || "/");
  } catch (e) {}
  event.waitUntil(
    clients.matchAll({ type: "window", includeUncontrolled: true }).then(function (clientList) {
      for (var i = 0; i < clientList.length; i++) {
        var c = clientList[i];
        if ("focus" in c) return c.focus();
      }
      if (clients.openWindow) return clients.openWindow(targetUrl || "/");
    })
  );
});

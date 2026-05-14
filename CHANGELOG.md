# Changelog

Notable changes pushed to `main` are listed here, newest first. Each line links behaviour to the **git commit** so you can inspect the exact diff with `git show <hash>`.

Older entries below were **reconstructed from existing git history** (same commits already on GitHub); new work should append under the current date (or under [Unreleased] until you cut a release).

## 2026-05-14

- **3c1f91f** — Monitoring High Sites: per-tab `flat` vs `high_sites` layout, named site groups, devices under groups with `site_group_id`, bulk import with `[Site]` headers, aggregate `hs_down` / `hs_up` web push per group (skip per-device push for grouped targets). Web push subscriptions gain `push_po` and `push_monitoring` with filtered sends; monitoring UI (tab mode, site group actions, subscribe JSON); related APIs and PO push path use `require_push_po`.

## 2026-05-13

- **2eb4ace** — PO approval reminders: cancel queued reminders when the workflow advances to the next approver (not only when the PO is fully finished). Fix a race where the notification worker could still send email/push after a row was cancelled, by claiming rows (`pending` → `dispatching`) and only marking `sent`/`failed` from that in-flight state.
- **359da3c** — PO Admin user flag: users with PO Admin can see all purchase orders; approve / decline / request changes / postpone only when they are the current primary or backup approver. Users screen to grant/revoke PO Admin; backup approvers aligned with approval logic.
- **606b503** — PO line items: recompute tax for API, PDF, and email surfaces; infer 15% VAT on legacy rows that had zero tax saved.
- **411aefb** — Notify the PO requester by email when every approval step has completed.
- **e48d820** — PO form: VAT basis toggle (ex VAT / inc VAT), numeric quantity as text field, tax display alignment.
- **708f03f** — When an HTML page is requested on the wrong Docker Compose published port, redirect to the service that owns that route (fixes “forbidden” navigation between services).
- **9f5ec7a** — Add `dr_promote.sh` to bring a standby environment and Compose stack back after DR promote.
- **14dd56f** — Standby: turn off clone scheduler (`CLONE_SCHEDULER_ENABLED`) and nightly self-clone behaviour.
- **0426323** — Optional `MTR_NAV_USE_PUBLISHED_PORTS` so clone deployments can navigate without nginx in front.

## 2026-05-12

- **8dbe41c** — Login page: “Business Management Platform” title and Wibernet logo.
- **b1c34d8** — Admin can reset a user’s 2FA; respect explicit per-user page grants instead of over-broad access.
- **7a4099d** — PO PDF: show creditors invoicing section; remove automatic email send tied to that flow.
- **79b4f82** — Fix `purchase_orders` service startup after invoice-email related changes.
- **2be99a7** — Email PO invoice PDFs to creditors (when configured/triggered for that path).
- **ff0fa9f** — Brand PO PDF exports with Wibernet filenames and company details.
- **125aa3e** — Rich PO approval emails (line items) and secure email action links for approve/decline/etc.
- **5617bec** — SMTP: support submission on port **465** with implicit TLS.
- **a816ec2** — Smoother PO role assignment saves; improved sample approval test emails.
- **5aaa22e** — Stock pre-allocation with **14-day** expiry; assign-stock UI can prefill from pre-allocated lines.

## 2026-05-11

- **99cca88** — Purchase orders: type picker, custom PO flow, and quote PDF import path.
- **b016357** — Initial import of application tree from production server (baseline snapshot).

---

### Maintainer note

After each meaningful push to `main`, add a bullet under the commit date with the **short hash** and a one-line **user-visible** description (what changed, what bug it fixes). If you later adopt [Semantic Versioning](https://semver.org/) and GitHub Releases, you can group these bullets under `## [1.x.x] - YYYY-MM-DD` instead of by calendar day.

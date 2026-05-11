# Agent / AI instructions

1. **[`docs/AI_SYSTEM_CONTEXT.md`](docs/AI_SYSTEM_CONTEXT.md) is the bible** — architecture, Docker layout, rebuild/restart (**`§3`**, **`§3.5`**). Framework and operations only; it overrides assumptions. Read before deploy/architecture answers. **Rebuild:** **`§3`**; never claim you don’t know how the app runs (default: repo `docker-compose.yml`). **Do not suggest Git.**

2. **Do not recommend `docker compose build`** until the project directory contains the **full** tree for `COPY . /app`. Prefer **`bash scripts/rebuild_services.sh <service>`** for deploy (preflight + build + `up -d`).

3. Follow **`.cursor/rules/non-negotiables.mdc`**: redundancy, mobile-first UX, security by default.

4. **Don’t assume — know.** Verify with the bible, the repo, and tools; never dress guesses up as certainty. If unverified, say so and how to verify.

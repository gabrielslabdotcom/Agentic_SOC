# Agentic SOC Analyst UI

Light product UI (Inbox-first) built with React + Vite + TypeScript + Tailwind. FastAPI serves the production build from `../src/agentic_soc/static/`. See the [root README](../README.md) for Ask Pop, connectors, and the four-plane model.

```bash
npm install
npm run dev      # http://127.0.0.1:5173 — proxies /tools to :8080
npm run build    # writes into ../src/agentic_soc/static
```

| Route | Page |
| ----- | ---- |
| `#/` | Inbox (metrics, Happening now, queue) |
| `#/i/:id` | Investigation |
| `#/search` | Ask Pop (natural-language search) |
| `#/directory` | Directory (Users \| Endpoints) |
| `#/exceptions` | Exceptions |
| `#/settings` | Settings (connectors + setup token) |

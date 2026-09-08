# Docs site (drop-in write-up)

GitLab-style instruction pages for Agentic SOC. Markdown is the source of truth for [gabrielslab.com Write-ups](https://gabrielslab.com/write-ups). The operator guide with lab-only secrets is still [`../SETUP_GUIDE.md`](../SETUP_GUIDE.md).

## Preview locally

Do **not** use the unauthenticated FastAPI on port 8080 for this.

```bash
cd docs/site
python3 -m http.server 8000
# open http://127.0.0.1:8000/
```

The sidebar loads each `.md` file in the browser. Opening `index.md` as a raw file will not show the chrome.

Optional later: MkDocs Material using [`nav.yaml`](nav.yaml).

## Pages

See [`nav.yaml`](nav.yaml). Hub content is [`index.md`](index.md); build-out including cloud is [`roadmap.md`](roadmap.md).

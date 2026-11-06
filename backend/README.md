# pcapvis backend (v2)

FastAPI backend for the PCAP Network Visualizer rebuild. See the repo-root
`README.md` and `REFACTOR.md` for the full picture.

```bash
uv sync                      # install (Python 3.12+)
uv run pcapvis check         # verify tshark is installed and recent enough
uv run pcapvis serve         # http://127.0.0.1:8000  (PCAPVIS_* env vars configure it)
uv run pytest                # tests
uv run ruff check .          # lint
```

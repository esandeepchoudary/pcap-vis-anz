"""Command line: pcapvis serve | check | analyze | create-user | db-upgrade | openapi."""

import argparse
import getpass
import json
import os
import sys

from pcapvis import __version__


def _cmd_check(args) -> int:
    from pcapvis.config import get_settings
    from pcapvis.tshark import check_tshark, install_hint

    s = get_settings()
    st = check_tshark(s.tshark_path, s.tshark_min_version)
    print(f"pcapvis {__version__} · mode={s.mode} · db={s.resolved_database_url.split('://')[0]}")
    print(("OK  " if st.ok else "FAIL ") + st.message)
    if not st.ok:
        print("\nInstall it:\n" + install_hint())
    return 0 if st.ok else 1


def _cmd_serve(args) -> int:
    import uvicorn

    from pcapvis.app import StartupError, create_app
    from pcapvis.config import get_settings

    s = get_settings()
    host = args.host or s.host
    port = args.port or s.port
    if args.reload:
        # Reload needs an import string; settings come from env vars in the child process.
        os.environ.setdefault("PCAPVIS_HOST", host)
        uvicorn.run(
            "pcapvis.cli:_reload_app",
            factory=True,
            host=host,
            port=port,
            reload=True,
            reload_dirs=[os.path.dirname(__file__)],
        )
        return 0
    try:
        app = create_app(s)
    except StartupError as exc:
        print(f"Cannot start pcapvis:\n{exc}", file=sys.stderr)
        return 1
    print(f"pcapvis {__version__} ({s.mode} mode) on http://{host}:{port}")
    uvicorn.run(app, host=host, port=port, proxy_headers=False)
    return 0


def _reload_app():
    from pcapvis.app import create_app

    return create_app()


def _cmd_create_user(args) -> int:
    from pcapvis.auth import service as auth
    from pcapvis.config import get_settings
    from pcapvis.db.migrate import upgrade_to_head
    from pcapvis.db.models import Role
    from pcapvis.db.session import make_engine, make_session_factory

    s = get_settings()
    password = os.environ.get("PCAPVIS_NEW_USER_PASSWORD") or getpass.getpass("Password: ")
    if not os.environ.get("PCAPVIS_NEW_USER_PASSWORD") and password != getpass.getpass("Repeat password: "):
        print("Passwords don't match.", file=sys.stderr)
        return 1
    s.data_dir.mkdir(parents=True, exist_ok=True)
    upgrade_to_head(s.resolved_database_url)
    engine = make_engine(s.resolved_database_url)
    try:
        with make_session_factory(engine)() as db:
            user = auth.create_user(db, args.username, password, Role(args.role), args.display_name or "")
    except auth.AuthError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    finally:
        engine.dispose()
    print(f"Created {user.role.value} '{user.username}'.")
    return 0


def _cmd_db_upgrade(args) -> int:
    from pcapvis.config import get_settings
    from pcapvis.db.migrate import upgrade_to_head

    s = get_settings()
    s.data_dir.mkdir(parents=True, exist_ok=True)
    upgrade_to_head(s.resolved_database_url)
    print("Database is up to date.")
    return 0


def _cmd_analyze(args) -> int:
    import time
    from collections import Counter
    from pathlib import Path

    from pcapvis.config import get_settings
    from pcapvis.engine.analyze import analyze_capture
    from pcapvis.engine.runner import CaptureError
    from pcapvis.tshark import check_tshark, install_hint

    s = get_settings()
    st = check_tshark(s.tshark_path, s.tshark_min_version)
    if not st.ok:
        print(f"{st.message}\n\nInstall it:\n{install_hint()}", file=sys.stderr)
        return 1
    path = Path(args.capture)
    if not path.is_file():
        print(f"No such file: {path}", file=sys.stderr)
        return 1

    def progress(fed, total, packets):
        if total and not args.quiet:
            print(f"\r  {fed * 100 // total:3d}%  {packets:,} packets", end="", file=sys.stderr, flush=True)

    start = time.time()
    try:
        r = analyze_capture(
            path,
            tshark_path=s.tshark_path,
            workers=args.workers,
            progress=progress,
            extract_objects=not args.no_files,
        )
    except CaptureError as exc:
        print(f"\n{exc}", file=sys.stderr)
        return 1
    elapsed = time.time() - start
    if not args.quiet:
        print(file=sys.stderr)
    if args.json:
        Path(args.json).write_text(r.model_dump_json(indent=2 if args.pretty else None))
    if args.quiet:
        return 0

    c = r.capture
    print(
        f"{c.file_name}: {c.packets:,} packets in {elapsed:.1f}s · {len(r.hosts)} hosts · {len(r.flows)} flows"
        + (" · TRUNCATED" if c.truncated else "")
    )
    types = Counter(h.host_type for h in r.hosts)
    print("\nHost types:  " + ", ".join(f"{t} {n}" for t, n in types.most_common()))
    levels = Counter(h.purdue_level for h in r.hosts)
    print(
        "Purdue:      "
        + ", ".join(
            f"L{lv:g} {n}" if lv >= 0 else f"unclassified {n}"
            for lv, n in sorted(levels.items(), reverse=True)
        )
    )
    ot = Counter((x.protocol, x.kind) for x in r.ot_commands if x.is_request or x.kind == "error")
    if ot:
        print("OT commands: " + ", ".join(f"{p} {k} {n}" for (p, k), n in sorted(ot.items())))
    if r.credentials:
        print(
            f"Credentials: {len(r.credentials)} in cleartext ("
            + ", ".join(sorted({x.protocol for x in r.credentials}))
            + ")"
        )
    if r.files:
        print(f"Files:       {len(r.files)} extracted, {sum(f.interesting for f in r.files)} flagged")
    sev = Counter(a.severity for a in r.anomalies)
    print(
        "Findings:    "
        + (
            ", ".join(f"{k} {sev[k]}" for k in ("critical", "high", "medium", "low", "info") if sev[k])
            or "none"
        )
    )
    for a in r.anomalies[: args.top]:
        print(f"  [{a.severity:8}] {a.description}")
    if len(r.anomalies) > args.top:
        print(f"  … {len(r.anomalies) - args.top} more (use --json for everything)")
    return 0


def _cmd_openapi(args) -> int:
    import tempfile
    from pathlib import Path

    from pcapvis.app import create_app
    from pcapvis.config import Settings

    with tempfile.TemporaryDirectory() as tmp:
        app = create_app(Settings(data_dir=Path(tmp), require_tshark=False, mode="server"))
        schema = app.openapi()
        app.state.engine.dispose()
    print(json.dumps(schema, indent=2, sort_keys=True))
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="pcapvis", description=f"PCAP Network Visualizer {__version__}")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("serve", help="Run the web app")
    sp.add_argument("--host")
    sp.add_argument("--port", type=int)
    sp.add_argument("--reload", action="store_true", help="Auto-reload on code changes (development)")
    sp.set_defaults(func=_cmd_serve)

    sub.add_parser("check", help="Check that tshark is installed").set_defaults(func=_cmd_check)

    cu = sub.add_parser("create-user", help="Create a user (server mode)")
    cu.add_argument("username")
    cu.add_argument("--role", default="consultant", choices=["admin", "lead", "consultant", "viewer"])
    cu.add_argument("--display-name")
    cu.set_defaults(func=_cmd_create_user)

    sub.add_parser("db-upgrade", help="Apply database migrations").set_defaults(func=_cmd_db_upgrade)

    an = sub.add_parser("analyze", help="Analyse a capture file and print a summary")
    an.add_argument("capture")
    an.add_argument("--json", metavar="FILE", help="Write the full result as JSON")
    an.add_argument("--pretty", action="store_true", help="Indent the JSON")
    an.add_argument("--workers", type=int, help="Parallel tshark workers (default: automatic)")
    an.add_argument("--no-files", action="store_true", help="Skip extracting transferred files")
    an.add_argument("--top", type=int, default=15, help="How many findings to print (default 15)")
    an.add_argument("--quiet", action="store_true", help="No output (use with --json)")
    an.set_defaults(func=_cmd_analyze)
    sub.add_parser("openapi", help="Print the OpenAPI schema (JSON)").set_defaults(func=_cmd_openapi)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

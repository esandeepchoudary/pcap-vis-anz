"""Command line: pcapvis serve | check | create-user | db-upgrade | openapi."""
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
        uvicorn.run("pcapvis.cli:_reload_app", factory=True, host=host, port=port, reload=True,
                    reload_dirs=[os.path.dirname(__file__)])
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
    sub.add_parser("openapi", help="Print the OpenAPI schema (JSON)").set_defaults(func=_cmd_openapi)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

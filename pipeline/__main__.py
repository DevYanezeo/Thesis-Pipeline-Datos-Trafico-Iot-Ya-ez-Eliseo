import sys


def _venv_hint() -> None:
    print(
        "En Manjaro/Arch no instale con pip en el Python del sistema (PEP 668).\n"
        "Use el entorno del repo:\n"
        "  bash scripts/setup-venv.sh\n"
        "  source .venv/bin/activate\n"
        "  pip install -e \".[ui]\"   # ya queda instalado si usó setup-venv.sh\n"
        "  python -m pipeline ui",
        file=sys.stderr,
    )


if __name__ == "__main__":
    try:
        from pipeline.cli import main
    except ModuleNotFoundError as exc:
        _venv_hint()
        print(f"Falta el módulo: {exc.name}", file=sys.stderr)
        raise SystemExit(2) from exc
    raise SystemExit(main())

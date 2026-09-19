from enum import StrEnum

from app.analysis.source.parser import ParsedModule


class FrameworkType(StrEnum):
    FASTAPI = "fastapi"
    FLASK = "flask"
    GENERIC = "generic"


_FASTAPI_SYMBOLS = {"FastAPI", "APIRouter", "Depends", "Security", "HTTPException"}
_FLASK_SYMBOLS = {"Flask", "Blueprint", "request", "jsonify", "url_for"}


def detect_framework(module: ParsedModule) -> FrameworkType:
    """Detects whether a Python source module is using FastAPI, Flask, or Generic Python."""
    # 1. Check direct imports
    for imp in module.imports:
        if imp == "fastapi" or imp.startswith("fastapi."):
            return FrameworkType.FASTAPI
        if imp == "flask" or imp.startswith("flask."):
            return FrameworkType.FLASK

    # 2. Check imported symbols
    for sym, mod in module.imported_symbols.items():
        if mod.startswith("fastapi") or sym in _FASTAPI_SYMBOLS:
            return FrameworkType.FASTAPI
        if mod.startswith("flask") or sym in _FLASK_SYMBOLS:
            return FrameworkType.FLASK

    # 3. Check decorator patterns on functions
    for fn in module.functions:
        for dec in fn.decorators:
            name = dec.name.lower()
            if any(
                name.endswith(f".{m}")
                for m in ("get", "post", "put", "delete", "patch", "options", "head")
            ):
                return FrameworkType.FASTAPI
            if name.endswith(".route") or name == "route":
                # Check keywords or args typical for Flask vs FastAPI
                if "methods" in dec.keywords:
                    return FrameworkType.FLASK
                return FrameworkType.FLASK

    return FrameworkType.GENERIC

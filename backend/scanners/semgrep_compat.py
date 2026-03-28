from __future__ import annotations

import contextlib
import os
import pathlib
import sys
import types


def _install_tracing_stub() -> None:
    class _DummyTracer:
        @contextlib.contextmanager
        def start_as_current_span(self, *args, **kwargs):
            yield

    class Traces:
        enabled = False

        def configure(self, *args, **kwargs):
            return None

        def extract(self):
            return None

        def inject(self):
            return None

        def set_scan_info(self, *args, **kwargs):
            return None

    module = types.ModuleType("semgrep.tracing")
    module.TRACER = _DummyTracer()
    module.TOP_LEVEL_SPAN_KIND = None
    module.Traces = Traces
    module.trace = lambda: (lambda func: func)
    sys.modules["semgrep.tracing"] = module


def _prepare_runtime_dirs() -> None:
    runtime_root = pathlib.Path(__file__).resolve().parents[1] / "data" / "tools" / "semgrep_runtime"
    home_dir = runtime_root / "home"
    temp_dir = runtime_root / "tmp"
    home_dir.mkdir(parents=True, exist_ok=True)
    temp_dir.mkdir(parents=True, exist_ok=True)

    os.environ.setdefault("PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION", "python")
    os.environ.setdefault("SEMGREP_ENABLE_VERSION_CHECK", "0")
    os.environ["SEMGREP_USER_HOME"] = str(home_dir)
    os.environ["HOME"] = str(home_dir)
    os.environ["USERPROFILE"] = str(home_dir)
    os.environ["TMP"] = str(temp_dir)
    os.environ["TEMP"] = str(temp_dir)


def main() -> None:
    _prepare_runtime_dirs()
    _install_tracing_stub()

    import semgrep.main

    raise SystemExit(semgrep.main.main())


if __name__ == "__main__":
    main()

"""Explicit native-TUN comparisons and isolated protocol interoperability."""

from __future__ import annotations

import signal
import sys
import unittest


def _interrupt(*_):
    raise KeyboardInterrupt("comparison interrupted")


def main(argv=None):
    values = list(sys.argv[1:] if argv is None else argv)
    if values == ["self-test"]:
        from .paths import BENCHMARK_ROOT

        suite = unittest.defaultTestLoader.discover(str(BENCHMARK_ROOT / "tests"))
        result = unittest.TextTestRunner(verbosity=1).run(suite)
        return 0 if result.wasSuccessful() and result.testsRun else 1
    stress = bool(values and values[0] == "stress")
    if stress:
        from .core_comparison import main as execute

        values.pop(0)
    elif values and values[0] == "experience":
        from .experience import main as execute

        values.pop(0)
    elif values and values[0] == "interop":
        from .interop.mihomo_interop import main as execute

        values.pop(0)
    else:
        from .core_comparison import main as execute
    if values and values[0] == "compare":
        values.pop(0)

    previous = signal.signal(signal.SIGTERM, _interrupt)
    try:
        return execute(values, stress=True) if stress else execute(values)
    except KeyboardInterrupt:
        return 130
    except (OSError, ValueError, RuntimeError) as error:
        print(f"container-benchmark: {error}", file=sys.stderr)
        return 1
    finally:
        signal.signal(signal.SIGTERM, previous)


if __name__ == "__main__":
    raise SystemExit(main())

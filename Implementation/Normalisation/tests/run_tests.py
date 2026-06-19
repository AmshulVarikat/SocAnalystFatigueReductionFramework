import importlib.util
import sys
import traceback
from pathlib import Path


def discover_and_run(tests_path: Path) -> int:
    sys.path.insert(0, str(tests_path.parents[2]))
    failures = 0
    for p in sorted(tests_path.glob('test_*.py')):
        name = p.stem
        spec = importlib.util.spec_from_file_location(name, p)
        mod = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(mod)  # type: ignore
        except Exception:
            print(f"ERROR importing {name}")
            traceback.print_exc()
            failures += 1
            continue

        for attr in dir(mod):
            if attr.startswith('test_') and callable(getattr(mod, attr)):
                func = getattr(mod, attr)
                try:
                    func()
                    print(f"OK: {name}.{attr}")
                except AssertionError:
                    print(f"FAIL: {name}.{attr}")
                    traceback.print_exc()
                    failures += 1
                except Exception:
                    print(f"ERROR running {name}.{attr}")
                    traceback.print_exc()
                    failures += 1

    return failures


if __name__ == '__main__':
    tests_path = Path(__file__).parent
    failures = discover_and_run(tests_path)
    if failures:
        print(f"{failures} test(s) failed")
        sys.exit(1)
    print("All tests passed")
    sys.exit(0)

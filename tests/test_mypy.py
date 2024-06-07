import pathlib
import sys
import mypy.api
import pytest

test_modules = ["rsa", "tests"]


@pytest.mark.parametrize("module", test_modules)
def test_run_mypy(module):
    proj_root = pathlib.Path(__file__).parent.parent
    args = [
        "--incremental",
        "--ignore-missing-imports",
        f"--python-version={sys.version_info.major}.{sys.version_info.minor}",
        str(proj_root / module)
    ]

    result = mypy.api.run(args)
    stdout, stderr, status = result

    messages = []
    if stderr:
        messages.append(stderr)
    if stdout:
        messages.append(stdout)
    if status:
        messages.append(f"Mypy failed with status {status}")

    if messages and not all("Success" in message for message in messages):
        pytest.fail("\n".join(["Mypy errors:"] + messages))

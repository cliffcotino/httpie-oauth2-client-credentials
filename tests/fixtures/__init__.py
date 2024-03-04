from dataclasses import dataclass
from io import BytesIO, StringIO

from httpie.context import Environment
from httpie.core import main


@dataclass
class CLIResponse:
    stdout: str
    stderr: str


class MockEnvironment(Environment):
    colors = 0
    show_displays = False
    stdin = None
    stdout_isatty = True
    stderr_isatty = True
    is_windows = False


def http(*args) -> CLIResponse:
    with BytesIO() as stdout, StringIO() as stderr:
        env = MockEnvironment(stdout=stdout, stderr=stderr)
        main(args=['http', *args], env=env)
        stdout.seek(0)
        stderr.seek(0)
        out = stdout.read().decode('utf8')
        err = stderr.read()
        r = CLIResponse(stdout=out, stderr=err)
    return r

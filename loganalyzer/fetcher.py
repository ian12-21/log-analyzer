import logging
import shlex
import subprocess
from typing import Protocol

import paramiko

# paramiko logs failures from its transport thread (with a traceback) even though
# the same failure also comes back as an exception, which we turn into a FetchError
logging.getLogger("paramiko").addHandler(logging.NullHandler())


class FetchError(Exception):
    """An error the user can understand - the CLI prints it without a traceback."""


class Runner(Protocol):
    def run(self, command: str, ok_codes: tuple[int, ...] = (0,)) -> str: ...


class LocalRunner:
    """The same commands, but run locally - for development and tests without a network."""

    def run(self, command: str, ok_codes: tuple[int, ...] = (0,)) -> str:
        p = subprocess.run(["bash", "-c", command], capture_output=True, text=True, errors="replace")
        if p.returncode not in ok_codes:
            raise FetchError(f"Command failed ({p.returncode}): {p.stderr.strip()}")
        return p.stdout


class SSHRunner:
    def __init__(self, host: str, user: str | None = None, port: int = 22,
                 key_filename: str | None = None, password: str | None = None) -> None:
        self.client = paramiko.SSHClient()
        self.client.load_system_host_keys()
        # an unknown host is refused, never added silently
        self.client.set_missing_host_key_policy(paramiko.RejectPolicy())
        # the order matters: the first two are subclasses of SSHException,
        # socket.timeout and NoValidConnectionsError are subclasses of OSError
        try:
            self.client.connect(host, port=port, username=user, key_filename=key_filename,
                                password=password, timeout=10)
        except paramiko.BadHostKeyException:
            raise FetchError("Host key does not match known_hosts - possible attack, aborting.") from None
        except paramiko.AuthenticationException:
            raise FetchError("Login failed - check the user, password or key.") from None
        except paramiko.SSHException as e:
            # e.g. the host is not in known_hosts
            raise FetchError(f"SSH error: {e}") from None
        except OSError as e:
            raise FetchError(f"Cannot connect to {host}:{port} ({e})") from None

    def run(self, command: str, ok_codes: tuple[int, ...] = (0,)) -> str:
        try:
            _, stdout, stderr = self.client.exec_command(command, timeout=60)
            # read the output BEFORE recv_exit_status(), otherwise a large output can block
            out = stdout.read().decode("utf-8", errors="replace")
            err = stderr.read().decode("utf-8", errors="replace")
            code = stdout.channel.recv_exit_status()
        except (paramiko.SSHException, OSError) as e:
            raise FetchError(f"SSH error while running the command: {e}") from None
        if code not in ok_codes:
            raise FetchError(f"Command failed ({code}): {err.strip()}")
        return out

    def close(self) -> None:
        self.client.close()

    def __enter__(self) -> "SSHRunner":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


# default for the summary: only the lines the parser understands
SUMMARY_PATTERN = "Failed|Accepted|Invalid user"


def grep_command(path: str, pattern: str = "sshd") -> str:
    # shlex.quote makes each input one argument, "--" stops grep from reading the pattern as an option
    return f"grep -E -- {shlex.quote(pattern)} {shlex.quote(path)}"


def fetch_lines(runner: Runner, path: str, pattern: str = "sshd") -> list[str]:
    # grep exits with 1 when nothing matches - that is not an error
    return runner.run(grep_command(path, pattern), ok_codes=(0, 1)).splitlines()

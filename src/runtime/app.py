"""Aplikacja-sonda do badania uzupelniajacego (konfiguracja uruchomieniowa).

Udostepnia dwa adresy:
  GET /       -> "ok", czyli czy aplikacja w ogole dziala w danym profilu
  GET /probe  -> JSON z tym, co moze zrobic kod wykonany w procesie aplikacji
                 (symulacja zdalnego wykonania kodu przez napastnika)

Tylko biblioteka standardowa Pythona, zeby ten sam plik dzialal na obrazach
standard, slim, alpine i distroless (distroless nie ma pip ani powloki).
Sonda niczego nie zmienia na stale: pliki testowe sa od razu usuwane.
"""

import json
import os
import socket
import stat
import tempfile
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = 8080

# Katalogi z programami sprawdzane wprost, bez polegania na zmiennej PATH.
BIN_DIRS = ("/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin")

SHELLS = ("sh", "bash", "dash", "ash", "zsh", "busybox")
PKG_MANAGERS = ("apt-get", "apt", "dpkg", "apk", "yum", "dnf", "microdnf", "rpm")
DOWNLOADERS = ("curl", "wget")
COMPILERS = ("gcc", "cc", "clang")


def read_status() -> dict:
    """Pola z /proc/self/status (uprawnienia, seccomp, no_new_privs)."""
    fields = {}
    with open("/proc/self/status", encoding="utf-8") as handle:
        for line in handle:
            key, _, value = line.partition(":")
            fields[key.strip()] = value.strip()
    return fields


def count_caps(hex_mask: str) -> int:
    """Liczba ustawionych bitow w masce uprawnien (CapEff, CapBnd)."""
    return bin(int(hex_mask, 16)).count("1")


def find_programs(names) -> list:
    """Sciezki programow z listy, ktore istnieja i sa wykonywalne."""
    found = []
    for directory in BIN_DIRS:
        # /bin bywa dowiazaniem do /usr/bin; licz kazdy katalog raz
        real_dir = os.path.realpath(directory)
        for name in names:
            path = os.path.join(real_dir, name)
            if path not in found and os.path.exists(path) and os.access(path, os.X_OK):
                found.append(path)
    return found


def can_write(directory: str) -> bool:
    path = os.path.join(directory, ".probe_write_test")
    try:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("x")
        os.remove(path)
        return True
    except OSError:
        return False


def setuid_files() -> list:
    """Pliki z bitem setuid w katalogach z programami (bez schodzenia nizej)."""
    found = []
    for directory in BIN_DIRS:
        try:
            names = os.listdir(directory)
        except OSError:
            continue
        for name in names:
            path = os.path.join(directory, name)
            try:
                info = os.lstat(path)
            except OSError:
                continue
            if stat.S_ISREG(info.st_mode) and info.st_mode & stat.S_ISUID:
                found.append(path)
    return sorted(set(os.path.realpath(p) for p in found))


def try_raw_socket() -> bool:
    """Gniazdo surowe wymaga uprawnienia CAP_NET_RAW."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.close()
        return True
    except OSError:
        return False


def try_chown():
    """Zmiana wlasciciela cudzego pliku wymaga CAP_CHOWN. None = brak miejsca na test."""
    try:
        fd, path = tempfile.mkstemp()
    except OSError:
        return None
    os.close(fd)
    try:
        os.chown(path, 12345, 12345)
        return True
    except OSError:
        return False
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


def try_read_shadow():
    """None = plik nie istnieje w obrazie."""
    try:
        with open("/etc/shadow", encoding="utf-8", errors="replace") as handle:
            handle.read(1)
        return True
    except FileNotFoundError:
        return None
    except OSError:
        return False


def read_cgroup(name: str):
    try:
        with open(os.path.join("/sys/fs/cgroup", name), encoding="utf-8") as handle:
            return handle.read().strip()
    except OSError:
        return None


def probe() -> dict:
    status = read_status()
    return {
        "uid": os.getuid(),
        "gid": os.getgid(),
        "cap_eff": status.get("CapEff"),
        "cap_eff_count": count_caps(status.get("CapEff", "0")),
        "cap_bnd_count": count_caps(status.get("CapBnd", "0")),
        "no_new_privs": status.get("NoNewPrivs"),
        "seccomp": status.get("Seccomp"),
        "seccomp_filters": int(status.get("Seccomp_filters", "0") or 0),
        "write_root": can_write("/"),
        "write_usr": can_write("/usr"),
        "shells": find_programs(SHELLS),
        "pkg_managers": find_programs(PKG_MANAGERS),
        "downloaders": find_programs(DOWNLOADERS),
        "compilers": find_programs(COMPILERS),
        "setuid_files": setuid_files(),
        "raw_socket": try_raw_socket(),
        "chown": try_chown(),
        "read_shadow": try_read_shadow(),
        "pids_max": read_cgroup("pids.max"),
        "memory_max": read_cgroup("memory.max"),
    }


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 (nazwa wymagana przez http.server)
        if self.path == "/":
            body = b"ok"
            content_type = "text/plain"
        elif self.path == "/probe":
            body = json.dumps(probe()).encode("utf-8")
            content_type = "application/json"
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # cisza w logach kontenera
        pass


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", PORT), Handler).serve_forever()

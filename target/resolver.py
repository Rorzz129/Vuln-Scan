import socket


def resolve_target(target: str) -> str | None:
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None


def reverse_resolve(ip: str) -> str | None:
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except socket.herror:
        return None
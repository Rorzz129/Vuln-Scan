from target.validator import validate_target
from target.resolver import resolve_target, reverse_resolve
from target.scope import Target
import ipaddress


def build_target(target_input: str) -> Target | None:

    if not validate_target(target_input):
        return None

    ip = resolve_target(target_input)

    if ip is None:
        return None

    hostname = None

    try:
        ipaddress.ip_address(target_input)

        hostname = reverse_resolve(ip)

    except ValueError:
        hostname = target_input

    return Target(
        original=target_input,
        hostname=hostname,
        ip=ip
    )
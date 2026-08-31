import ipaddress  # check si c une adresse IP valide
import re

def validip(target: str) -> bool:
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def is_valid_domain(target: str) -> bool:
    pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    return re.match(pattern, target) is not None


def validate_target(target: str) -> bool:
    return validip(target) or is_valid_domain(target)
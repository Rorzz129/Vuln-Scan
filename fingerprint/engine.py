from typing import Any


def fingerprint_nmap(
    nmap_results: dict[int, dict[str, Any]]
) -> list[dict[str, Any]]:

    technologies = []

    ignored_services = {
        "tcpwrapped"
    }

    ignored_products = {
        "scaffolding on HTTPServer2"
    }

    for port, service_data in nmap_results.items():

        service = service_data.get("service")
        product = service_data.get("product")
        version = service_data.get("version")
        extra = service_data.get("extra")

        if service in ignored_services:
            continue

        if product in ignored_products:
            continue

        if not product and not service:
            continue

        technology = {
            "name": product or service,
            "version": version,
            "service": service,
            "port": port,
            "extra": extra,
            "source": "nmap"
        }

        technologies.append(
            technology
        )

    return technologies
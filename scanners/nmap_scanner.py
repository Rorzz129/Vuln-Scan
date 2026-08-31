import json
import shutil
import subprocess


def check_nmap() -> bool:
    return shutil.which("nmap") is not None


def scan_target(
    target: str,
    ports: str = "21,22,25,53,80,110,143,443,445,3306,3389,5432,8080"
) -> dict:

    if not check_nmap():
        raise RuntimeError(
            "Nmap is not installed or not available in PATH"
        )

    command = [
        "nmap",
        "-sV",
        "-Pn",
        "-p",
        ports,
        "-oX",
        "-",
        target
    ]

    process = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    if process.returncode != 0:
        raise RuntimeError(
            process.stderr.strip()
        )

    return parse_nmap_xml(
        process.stdout
    )


def parse_nmap_xml(
    xml_data: str
) -> dict:

    import xml.etree.ElementTree as ET

    root = ET.fromstring(xml_data)

    results = {}

    for host in root.findall("host"):

        ports = host.find("ports")

        if ports is None:
            continue

        for port in ports.findall("port"):

            port_id = int(
                port.get("portid")
            )

            state = port.find("state")

            if state is None:
                continue

            if state.get("state") != "open":
                continue

            service = port.find("service")

            service_data = {
                "state": state.get("state"),
                "protocol": port.get("protocol"),
                "service": None,
                "product": None,
                "version": None,
                "extra": None
            }

            if service is not None:

                service_data.update({
                    "service": service.get("name"),
                    "product": service.get("product"),
                    "version": service.get("version"),
                    "extra": service.get("extrainfo")
                })

            results[port_id] = service_data

    return results

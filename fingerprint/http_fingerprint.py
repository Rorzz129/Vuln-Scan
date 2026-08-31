def fingerprint_http(
    http_data: dict
) -> list[dict]:

    technologies = []

    if not http_data:

        return technologies

    headers = http_data.get(
        "headers",
        {}
    )

    if not headers:

        return technologies

    normalized_headers = {
        key.lower(): value
        for key, value in headers.items()
    }

    server = normalized_headers.get(
        "server"
    )

    powered_by = normalized_headers.get(
        "x-powered-by"
    )

    port = http_data.get(
        "port"
    )

    if server:

        server_name = server
        server_version = None

        parts = server.split(
            "/",
            1
        )

        if len(parts) == 2:

            server_name = parts[0].strip()
            server_version = parts[1].strip()

        technologies.append(
            {
                "name": server_name,
                "version": server_version,
                "port": port
            }
        )

    if powered_by:

        powered_name = powered_by
        powered_version = None

        parts = powered_by.split(
            "/",
            1
        )

        if len(parts) == 2:

            powered_name = parts[0].strip()
            powered_version = parts[1].strip()

        technologies.append(
            {
                "name": powered_name,
                "version": powered_version,
                "port": port
            }
        )

    return technologies
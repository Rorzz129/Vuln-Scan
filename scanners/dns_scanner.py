import dns.resolver


def query_dns_records(
    domain: str,
    record_type: str
) -> list[str]:
    records = []

    try:
        answers = dns.resolver.resolve(
            domain,
            record_type
        )
        for answer in answers:

            record = answer.to_text().strip('"')

            records.append(record)

    except (
        dns.resolver.NoAnswer,
        dns.resolver.NXDOMAIN,
        dns.resolver.NoNameservers,
        dns.exception.Timeout
    ):
        pass

    return records

def scan_dns(domain: str) -> dict[str, list[str]]:
    record_types = [
        "A",
        "AAAA",
        "MX",
        "NS",
        "TXT",
        "CNAME"
    ]
    results = {}
    for record_type in record_types:

        results[record_type] = query_dns_records(
            domain,
            record_type
        )

    return results

if __name__ == "__main__":
    results = scan_dns("example.com")

    for record_type, records in results.items():

        print(f"\n[{record_type}]")

        for record in records:
            print(f"  {record}")
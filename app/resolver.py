import socket
from typing import List, Optional

from app import builder, dependencies
from app.package.data import DNSPackage, QueryClass, QueryType

settings = dependencies.get_server_settings()


def resolve(
    q_request: bytes,
    server_ip: str = settings["root_server_ip"],
    server_port: int = settings["root_server_port"],
) -> Optional[DNSPackage]:
    response = _ask_dns_server(q_request, server_ip, server_port)
    response_package = DNSPackage(response)

    if response_package.header.an_count > 0:
        return response_package

    if response_package.header.ns_count > 0:
        for ar in response_package.authoritative_records:
            for ad_r in response_package.additional_records:
                if ad_r.r_type == QueryType.A:
                    return resolve(q_request, ad_r.r_data)

            for ip in _get_ips_by_name(response_package.header.id, ar.r_data):
                return resolve(q_request, ip)


def _get_ips_by_name(
    r_id: int,
    name: str,
    server_ip: str = settings["root_server_ip"],
    server_port: int = settings["root_server_port"],
) -> Optional[List[str]]:
    q_request = builder.get_request(
        r_id,
        name,
        QueryType.A,
        QueryClass.IN,
    )

    resolver_package = resolve(q_request, server_ip, server_port)

    if resolver_package is not None:
        return [ra.r_data for ra in resolver_package.answer_records]


def _ask_dns_server(request: bytes, dns_server_ip: str, dns_server_port=53) -> bytes:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(5)
        sock.connect((dns_server_ip, dns_server_port))
        sock.settimeout(None)
        sock.send(request)
        return sock.recv(settings["request_size"])

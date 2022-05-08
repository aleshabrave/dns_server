import socket
from typing import List

from app import dependencies
from app.cacher import DNSCacher
from app.package import (
    DNSPackage,
    DNSResourceRecord,
    QueryType,
    get_response_dns_package_data,
)

server_settings = dependencies.get_server_settings()


class DNSServer:
    def __init__(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server_socket.bind(("127.0.0.1", server_settings["server_port"]))
        # self._init_cacher()

    def _init_cacher(self):
        self._cacher = DNSCacher(server_settings["path_to_backup"])
        self._cacher.make_migration()

    def run(self):
        while True:
            self._handle_client()

    def _handle_client(self):
        request, address = self.server_socket.recvfrom(server_settings["request_size"])
        response = self._get_response(request)
        self.server_socket.sendto(response, address)

    def _get_response(self, request):
        request = DNSPackage(request)
        all_answer_records = []

        for question in request.questions:
            # answer_records = self._cacher.get(question.q_name, question.q_type)

            # if answer_records is None:
            answer_records = self._get_answer_records_from_other_dns_server(request)
            # self._cacher.add(question.q_name, question.q_type, answer_records)

            all_answer_records += answer_records

        return get_response_dns_package_data(
            request.header, request.questions, all_answer_records
        )

    def _get_answer_records_from_other_dns_server(
        self, request: DNSPackage
    ) -> List[DNSResourceRecord]:
        response = self._ask_dns_server(
            request.data,
            server_settings["root_dns_server_ip"],
            server_settings["root_dns_server_port"],
        )

        while response.header.an_count == 0 and response.header.ar_count > 0:
            for record in response.additional_records:
                if record.r_type == QueryType.A.value:
                    response = self._ask_dns_server(request.data, record.r_data)
                    break

        return response.answer_records

    @staticmethod
    def _ask_dns_server(request, dns_server_ip, dns_server_port=53) -> DNSPackage:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect((dns_server_ip, dns_server_port))
            sock.send(request)
            response = sock.recv(server_settings["request_size"])
        return DNSPackage(response)

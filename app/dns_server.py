import signal
import socket
from typing import List

from app import dependencies
from app.cacher import DNSCacher
from app.package import (
    DNSPackage,
    DNSResourceRecord,
    QueryType,
    get_response_dns_package_data,
    get_unsupported_response_dns_package_data,
)

server_settings = dependencies.get_server_settings()


class DNSServer:
    def __init__(self):
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._server_socket.bind(("127.0.0.1", server_settings["server_port"]))
        self._init_cacher()
        self._handle_flag = True
        signal.signal(signal.SIGINT, self.close)

    def _init_cacher(self):
        self._cacher = DNSCacher(
            server_settings["path_to_cache"], server_settings["clean_period"]
        )
        self._cacher.load()
        self._cacher.start()

    def run(self):
        while self._handle_flag:
            self._handle_client()

    def close(self, _, __):
        self._handle_flag = False
        self._server_socket.close()
        self._cacher.save()
        self._cacher.close()

    def _handle_client(self):
        request, address = self._server_socket.recvfrom(server_settings["request_size"])
        response = self._get_response(request)
        self._server_socket.sendto(response, address)

    def _get_response(self, r):
        def __get_response(request):
            request = DNSPackage(request)
            all_answer_records = []

            for question in request.questions:
                answer_records = self._cacher.get(question.q_name, question.q_type)

                if answer_records is None:
                    answer_records = self._get_answer_records_from_other_dns_server(
                        request, question.q_type
                    )
                    self._cacher.add(question.q_name, question.q_type, answer_records)

                all_answer_records += answer_records

            return get_response_dns_package_data(
                request.header, request.questions, all_answer_records
            )

        try:
            return __get_response(r)
        except Exception as e:
            print(e)
            return get_unsupported_response_dns_package_data(r[:2])

    def _get_answer_records_from_other_dns_server(
        self, request: DNSPackage, q_type: QueryType
    ) -> List[DNSResourceRecord]:
        response = self._ask_dns_server(
            request.data,
            server_settings["root_dns_server_ip"],
            server_settings["root_dns_server_port"],
        )
        response = self._find_good_response(request, response, q_type)
        return response.answer_records if response is not None else []

    @staticmethod
    def _find_good_response(
        request: DNSPackage, response: DNSPackage, q_type: QueryType
    ) -> DNSPackage:
        if response.header.an_count != 0:
            return response

        if response.header.ar_count > 0:

            for record in response.additional_records:
                if record.r_type == QueryType.A.value:
                    good_response = DNSServer._find_good_response(
                        request,
                        DNSServer._ask_dns_server(request.data, record.r_data),
                        q_type,
                    )
                    if good_response is not None:
                        return good_response

        if q_type == QueryType.NS.value and response.header.ns_count > 0:
            response.answer_records = response.authoritative_records
            return response

    @staticmethod
    def _ask_dns_server(request, dns_server_ip, dns_server_port=53) -> DNSPackage:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(5)
            sock.connect((dns_server_ip, dns_server_port))
            sock.settimeout(None)
            sock.send(request)
            response = sock.recv(server_settings["request_size"])
        return DNSPackage(response)

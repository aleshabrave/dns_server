import signal
import socket

from app import Cacher, builder, dependencies, resolver

settings = dependencies.get_server_settings()


class Server:
    def __init__(self):
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._server_socket.bind((settings["server_ip"], settings["server_port"]))
        self._init_cacher()
        self._handle_flag = True
        signal.signal(signal.SIGINT, self._close)

    def _init_cacher(self):
        self._cacher = Cacher(settings["cache_filepath"], settings["clean_period"])
        self._cacher.load()
        self._cacher.start()

    def run(self):
        while self._handle_flag:
            self._handle_client()

    def _handle_client(self):
        request, address = self._server_socket.recvfrom(settings["request_size"])
        response = self._get_response(request)
        self._server_socket.sendto(response, address)

    @staticmethod
    def _get_response(request: bytes) -> bytes:
        try:
            return resolver.resolve(q_request=request).data
        except Exception as e:
            print(e)
            return builder.get_unsupported_response(request[:2])

    def _close(self, _, __):
        self._handle_flag = False
        self._server_socket.close()
        self._cacher.save()
        self._cacher.close()

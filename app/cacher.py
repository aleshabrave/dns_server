import struct
from typing import Dict, List

from app.package import DNSResourceRecord, QueryType


class DNSCacher:
    def __init__(self, path):
        self.path: str = path
        self.buffer: Dict[str, Dict[QueryType, List[DNSResourceRecord]]] = {}

    def migrate_up(self):
        with open(self.path, "rb") as file:
            pass

    def add(
        self, q_name: str, q_type: QueryType, answer_records: List[DNSResourceRecord]
    ):
        if q_name not in self.buffer:
            self.buffer[q_name] = {}
        if q_type not in self.buffer[q_name]:
            self.buffer[q_name][q_type] = answer_records

    def get(self, q_name: str, q_type: QueryType):
        if q_name in self.buffer and q_type in self.buffer[q_name]:
            return self.buffer[q_name][q_type]

    def make_migration(self):
        with open(self.path, "wb") as file:
            pass

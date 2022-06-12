import struct
from dataclasses import dataclass
from enum import Enum
from typing import List


class QueryType(int, Enum):
    A = 1
    NS = 2
    PTR = 12
    AAAA = 28


class QueryClass(int, Enum):
    IN = 1


@dataclass
class DNSHeader:
    id: int
    flags: int
    qd_count: int
    an_count: int
    ns_count: int
    ar_count: int


@dataclass
class DNSQuestion:
    q_name: str
    q_type: QueryType
    q_class: QueryClass


@dataclass
class DNSResourceRecord:
    r_name: str
    r_type: QueryType
    r_class: QueryClass
    r_ttl: int
    rd_length: int
    r_data: str


@dataclass
class DNSPackage:
    data: bytes
    _pointer: int = 0
    header: DNSHeader = None
    questions: List[DNSQuestion] = None
    answer_records: List[DNSResourceRecord] = None
    authoritative_records: List[DNSResourceRecord] = None
    additional_records: List[DNSResourceRecord] = None

    def __post_init__(self):
        self.questions = []
        self.answer_records = []
        self.authoritative_records = []
        self.additional_records = []
        self._init_header()
        self._init_questions()
        self._init_resource_records()

    def _init_header(self):
        step = 12
        self.header = DNSHeader(*struct.unpack("!6H", self.data[:step]))
        self._pointer += step

    def _init_questions(self):
        step = 4
        for _ in range(self.header.qd_count):
            self.questions.append(
                DNSQuestion(
                    self._parse_name(),
                    *struct.unpack(
                        "!HH", self.data[self._pointer : self._pointer + step]
                    ),
                )
            )
            self._pointer += step

    def _init_resource_records(self):
        rrs = (
            (self.answer_records, self.header.an_count),
            (self.authoritative_records, self.header.ns_count),
            (self.additional_records, self.header.ar_count),
        )
        [self._init_resource_record(*rr) for rr in rrs]

    def _init_resource_record(self, buf, length):
        step = 10
        for _ in range(length):
            r_name = self._parse_name()
            r_type, r_class, r_ttl, rd_length = struct.unpack(
                "!HHIH", self.data[self._pointer : self._pointer + step]
            )
            self._pointer += step
            r_data = self._parse_resource_body(r_type, rd_length)
            buf.append(
                DNSResourceRecord(r_name, r_type, r_class, r_ttl, rd_length, r_data)
            )

    def _parse_name(self):
        name_list = []
        position = self._pointer
        flag = False
        while True:
            if self.data[position] > 63:
                if not flag:
                    self._pointer = position + 2
                    flag = True
                position = ((self.data[position] - 192) << 8) + self.data[position + 1]
                continue
            else:
                length = self.data[position]
                if length == 0:
                    if not flag:
                        self._pointer = position + 1
                    break
                position += 1
                name_list.append(self.data[position : position + length])
                position += length
        name = ".".join([i.decode("ascii") for i in name_list])
        return name

    def _parse_resource_body(self, r_type, rd_length):
        if r_type == QueryType.A.value:
            ipv4_address = struct.unpack(
                f"!{rd_length}B",
                self.data[self._pointer : self._pointer + rd_length],
            )
            data = ".".join(str(octet) for octet in ipv4_address)
            self._pointer += rd_length
        elif r_type == QueryType.NS.value or r_type == QueryType.PTR.value:
            data = self._parse_name()
        elif r_type == QueryType.AAAA.value:
            ipv6_address = struct.unpack(
                f"!{rd_length // 2}H",
                self.data[self._pointer : self._pointer + rd_length],
            )
            data = ":".join(str(hex(octet))[2:] for octet in ipv6_address)
            self._pointer += rd_length
        else:
            raise Exception(f"Unsupported query type={r_type}")
        return data

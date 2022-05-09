import struct
from dataclasses import dataclass
from enum import Enum
from typing import List, Tuple


class QueryType(Enum):
    A = 1
    NS = 2
    PTR = 12
    AAAA = 28


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
    q_class: str


@dataclass
class DNSResourceRecord:
    r_name: str
    r_type: QueryType
    r_class: str
    r_ttl: str
    rd_length: int
    r_data: str


class DNSPackage:
    def __init__(self, data: bytes):
        self.data = data
        self._pointer = 0
        self._init_header()
        self._init_questions()
        self._init_resource_records()

    def _init_header(self):
        step = 12
        self.header = DNSHeader(*struct.unpack("!6H", self.data[:step]))
        self._pointer += step

    def _init_questions(self):
        self.questions = []
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
        self.answer_records: List[DNSResourceRecord] = []
        self.authoritative_records: List[DNSResourceRecord] = []
        self.additional_records: List[DNSResourceRecord] = []
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
        elif r_type == QueryType.NS.value:
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


def get_response_dns_package_data(
    req_header: DNSHeader,
    req_questions: List[DNSQuestion],
    res_answer_records: List[DNSResourceRecord],
) -> bytes:
    package = struct.pack(
        "!6H",
        *[
            req_header.id,
            (2 << 14) + (2 << 9),
            len(req_questions),
            len(res_answer_records),
            0,
            0,
        ],
    )

    for question in req_questions:
        package += _pack_domain_name(question.q_name)[1] + struct.pack(
            "!HH", *[question.q_type, question.q_class]
        )

    for answer in res_answer_records:
        package += (
            _pack_domain_name(answer.r_name)[1]
            + struct.pack("!HHI", answer.r_type, answer.r_class, answer.r_ttl)
            + _pack_resource_data(answer.r_type, answer.rd_length, answer.r_data)
        )

    return package


def _pack_resource_data(r_type, rd_length, r_data) -> bytes:
    if r_type == QueryType.A.value:
        data = struct.pack(f"!H{rd_length}B", 4, *map(int, r_data.split(".")))
    elif r_type == QueryType.NS.value:
        rd_length, data = _pack_domain_name(r_data)
        data = struct.pack("!H", rd_length) + data
    elif r_type == QueryType.AAAA.value:
        data = struct.pack(f"!H{rd_length // 2}H", 16, r_data.split(":"))
    else:
        raise Exception(f"Unsupported query type={r_type}")
    return data


def _pack_domain_name(domain_name) -> Tuple[int, bytes]:
    package = bytes()
    labels = [(len(name), name) for name in domain_name.split(".")]

    for label in labels:
        package += struct.pack(f"!B", label[0]) + label[1].encode()
    package += struct.pack("!B", 0)
    return len(labels) + sum([label[0] for label in labels]) + 1, package

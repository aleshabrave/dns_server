import struct
from typing import List, Tuple

from app.package.data import (
    DNSHeader,
    DNSQuestion,
    DNSResourceRecord,
    QueryClass,
    QueryType,
)


def get_unsupported_response(h_id: bytes) -> bytes:
    return h_id + struct.pack(
        "!5H",
        *[
            (2 << 14) + (2 << 9) + (2 << 2),
            0,
            0,
            0,
            0,
        ],
    )


def get_response(
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
            + _pack_r_data(answer.r_type, answer.rd_length, answer.r_data)
        )

    return package


def _pack_r_data(r_type, rd_length, r_data) -> bytes:
    if r_type == QueryType.A.value:
        data = struct.pack(f"!H{rd_length}B", 4, *map(int, r_data.split(".")))
    elif r_type == QueryType.NS.value or r_type == QueryType.PTR.value:
        rd_length, data = _pack_domain_name(r_data)
        data = struct.pack("!H", rd_length) + data
    elif r_type == QueryType.AAAA.value:
        octets = [int(octet, 16) for octet in r_data.split(":")]
        data = struct.pack(f"!H{rd_length // 2}H", 16, *octets)
    else:
        raise Exception(f"Unsupported query type={r_type}")
    return data


def _pack_domain_name(domain_name: str) -> Tuple[int, bytes]:
    package = bytes()
    labels = [(len(name), name) for name in domain_name.split(".")]

    for label in labels:
        package += struct.pack(f"!B", label[0]) + label[1].encode()
    package += struct.pack("!B", 0)
    return len(labels) + sum([label[0] for label in labels]) + 1, package


def _pack_question(q_data: str, q_type: QueryType, q_class: QueryClass) -> bytes:
    _, data = _pack_domain_name(q_data)
    return data + struct.pack("!2H", *[q_type, q_class])


def get_request(
    r_id: int, domain_name: str, q_type: QueryType, q_class: QueryClass
) -> bytes:
    return struct.pack(
        "!6H",
        *[r_id, 0, 1, 0, 0, 0],
    ) + _pack_question(q_data=domain_name, q_type=q_type, q_class=q_class)

"""
Simple implementation of BMP on Scapy.
BMP is defined in RFC 7854.
MVP to be able to prototype TLVs using https://tools.ietf.org/html/draft-ietf-grow-bmp-tlv-02.
Most of the code here is based on the bgp implementation of scapy
"""
import binascii
from scapy.packet import Packet, bind_layers
from scapy.layers.inet import TCP
from scapy.fields import (
    ShortField,
    ByteEnumField,
    ByteField,
    Field,
    IntField,
    IntEnumField,
    StrLenField,
    FlagsField,
    FieldLenField,
    PacketListField,
    PacketField,
    ShortEnumField,
)
from scapy.config import conf
from scapy.all import rdpcap
from bgp import BGPUpdate, BGPOpen, BGPFieldIPv6, IP6Field, BGP
import bgp
import struct

bgp.bgp_module_conf.use_2_bytes_asn = False


_bmp_message_types = {
    0: "ROUTE MONITORING",
    1: "STATISTICS",
    2: "PEER DOWN NOTIFICATION",
    3: "PEER UP NOTIFICATION",
    4: "INITIATION MESSAGE",
    5: "TERMINATION MESSAGE",
    6: "ROUTE MIRROING MESSAGE",
}


# Status flags from https://www.ietf.org/archive/id/draft-cppy-grow-bmp-path-marking-tlv-07.txt
_bmp_status_flags = {
    # "Unknown": 0,
    "Invalid": 0,
    "Best": 1,
    "Non-selected": 2,
    "Primary": 3,
    "Backup": 4,
    "Non-installed": 5,
    "Best-external": 6,
    "Add-Path": 7,
    "bit8": 8,
    "bit9": 9,
}

# Convert the status name to position into an array
bmp_status_array = [f"NA{n}" for n in range(0, 8 * 4)]
for state, pos in _bmp_status_flags.items():
    bmp_status_array[pos] = state


# Reason codes from https://www.ietf.org/archive/id/draft-cppy-grow-bmp-path-marking-tlv-07.txt
_bmp_reason_codes = {
    0x0000: "invalid for unknown",
    0x0001: "invalid for super network",
    0x0002: "invalid for dampening",
    0x0003: "invalid for history",
    0x0004: "invalid for policy deny",
    0x0005: "invalid for ROA not validation",
    0x0006: "invalid for interface error",
    0x0007: "invalid for nexthop route unreachable",
    0x0008: "invalid for nexthop tunnel unreachable",
    0x000F: "invalid for nexthop restrain",
    0x0010: "invalid for relay BGP LSP",
    0x0014: "invalid for being inactive within VPN instance",
    0x0015: "invalid for prefix-sid not exist",
    0x0200: "not preferred for peer address",
    0x0300: "not preferred for router ID",
    0x0400: "not preferred for Cluster List",
    0x0500: "not preferred for IGP cost",
    0x0600: "not preferred for peer type",
    0x0700: "not preferred for MED",
    0x0800: "not preferred for origin",
    0x0900: "not preferred for AS-Path",
    0x0A00: "not preferred for route type",
    0x0B00: "not preferred for Local_Pref",
    0x0C00: "not preferred for PreVal",
    0x0F00: "not preferred for not direct route",
    0x1000: "not preferred for nexthop bit error",
    0x1100: "not preferred for received path-id",
    0x1200: "not preferred for validation",
    0x1300: "not preferred for originate IP",
    0x1500: "not preferred for route distinguisher",
    0x1600: "not preferred for route-select delay",
    0x1700: "not preferred for being imported route",
    0x1800: "not preferred for med-plus-igp",
    0x1C00: "not preferred for AIGP",
    0x1D00: "not preferred for nexthop-resolved aigp",
    0x2000: "not preferred for nexthop unreachable",
    0x2100: "not preferred for nexthop IP",
    0x2300: "not preferred for high-priority",
    0x2400: "not preferred for nexthop-priority",
    0x2500: "not preferred for process ID",
    0xFFFF: "no reason code",
}


class PerPeerHeader(Packet):
    name = "PEERPEERHEADER"
    fields_desc = [
        ByteField("type", 0),
        FlagsField(
            "peer_flags", 0, 8, ["NA0", "NA1", "NA2", "NA3", "NA4", "A", "L", "V"]
        ),
        # How to do a 16 bytes field?
        Field("peer_distinquisher", 0, fmt="Q"),
        IP6Field("peer_address", "::/0"),
        IntField("peer_asn", 0),
        IntField("peer_bgp_id", 0),
        IntField("timestamp_seconds", 0),
        IntField("timestamp_microseconds", 0),
    ]

    def extract_padding(self, p):
        return "", p


class BMPInformationTLV(Packet):
    name = "InformationTlV"
    fields_desc = [
        ShortField("Type", 0),
        FieldLenField("length", None, fmt="H", length_of="information"),
        StrLenField("information", "", length_from=lambda p: p.length),
    ]

    def extract_padding(self, p):
        return "", p


class BMPTerminationTLV(Packet):
    name = "BGPTerminationTLV"
    fields_desc = [
        ShortField("type", 0),
        FieldLenField("length", None, fmt="H", length_of="information"),
        StrLenField("value", "", length_from=lambda p: p.length),
    ]


class BMPInitiation(Packet):
    name = "BMPInitiation"
    fields_desc = [PacketListField("information", [], BMPInformationTLV)]


class BMPPeerUpNotificationInfo(Packet):
    name = "BMPPeerUpNotificationInfo"
    fields_desc = [
        IP6Field("local_address", "::/0"),
        ShortField("local_port", 0),
        ShortField("remote_port", 0),
        PacketField("sent_open", None, BGP),
        PacketField("received_open", None, BGP),
        PacketField("information", None, BMPInformationTLV),
    ]

    def extract_padding(self, p):
        return "", p


class BMPPeerUp(Packet):
    name = "BMPPeerUp"
    fields_desc = [
        PacketField("per_peer_header", None, PerPeerHeader),
        PacketField("info", None, BMPPeerUpNotificationInfo),
    ]


class BMPStatsCounter(Packet):
    name = "BMPStatsCounter"
    fields_desc = [
        ShortField("Type", 0),
        FieldLenField("length", None, fmt="H", length_of="information"),
        StrLenField("information", "", length_from=lambda p: p.length),
    ]


class BMPStats(Packet):
    name = "BMPStats"
    fields_desc = [
        PacketField("PerPeer", None, PerPeerHeader),
        FieldLenField("len", None, count_of="counters"),
        PacketListField(
            "counters", None, BMPStatsCounter, count_from=lambda pkt: pkt.len
        ),
    ]

class BMPPeerDown(Packet):
    name = "BMPPeerDown"
    fields_desc = [
        ByteField("reason", 1),
        # TODO: add optional field Data, used for different reasons.
    ]


class BMPTermination(Packet):
    name = "BMPTermination"
    fields_desc = [PacketListField("information", [], BMPTerminationTLV)]


class OptionalField:
    """
    An optional field that might appear or not in the packet.
    Not sure if this is implemented already. I could not find it.
    I took the implementation from conditional, but without the condition.
    Doing a FieldListField was also an option, but did not want to add
     an extra property to get the value of the reason: (tlv.reasons.reason)
    As with FieldListField, having a optional list only makes sense at the end of the packet.
    """

    __slots__ = ["fld", "cond"]

    def __init__(self, fld):
        self.fld = fld

    def getfield(self, pkt, s):
        if s and pkt:
            return self.fld.getfield(pkt, s)
        return s, None

    def addfield(self, pkt, s, val):
        if val:
            return self.fld.addfield(pkt, s, val)
        return s

    def __getattr__(self, attr):
        return getattr(self.fld, attr)

# Next are the TLV packets, and the implementation of Path status
# TLV is defined in https://tools.ietf.org/html/draft-ietf-grow-bmp-tlv-03
# Path status is defined in https://tools.ietf.org/html/draft-ietf-grow-bmp-tlv-02.

class TLVPathStatus(Packet):
    fields_desc = [
        ShortField("index", 0),
        FlagsField("status", 0, 32, bmp_status_array),
        OptionalField(ShortEnumField("reason", None, _bmp_reason_codes)),
    ]


class TLVPathStatusEnterprise(Packet):
    fields_desc = [
        IntField("pen", 343),
        ShortField("index", 0),
        FlagsField("status", 0, 32, bmp_status_array),
        OptionalField(ShortEnumField("reason", None, _bmp_reason_codes)),
    ]


class BMPTLVPaolo(Packet):
    fields_desc = [
        ShortField("type", 0),
        FieldLenField("length", None, fmt="H", length_of="value"),
        PacketField("value", None, TLVPathStatus),
    ]

    def extract_padding(self, p):
        return "", p


# Back to BMP packets.

class BMPRouteMonitoring(Packet):
    name = "BMPRouteMonitoring"
    fields_desc = [
        PacketField("per_peer", None, PerPeerHeader),
        PacketField("bgp_update", None, BGP),
        PacketListField("tlv", [], BMPTLVPaolo),
    ]


class BMPRouteMirroing(Packet):
    name = "BMPRouteMirror"
    fields_desc = [
        ShortField("Type", 0),
        FieldLenField("length", None, fmt="H", length_of="data"),
        StrLenField("data", "", length_from=lambda p: p.length),
    ]


class BMPHeader(Packet):
    """
    The header of any BMP message.
    References: https://tools.ietf.org/html/rfc7854,
    """

    name = "BMPHeader"
    fields_desc = [
        ByteField("version", 4),
        IntField("len", None),
        ByteEnumField("type", 0, _bmp_message_types),
    ]

    def post_build(self, p, pay):
        if self.len is None:
            length = len(p)
            if pay:
                length = length + len(pay)
            position_after_length = self.fields_desc[0].sz + self.fields_desc[1].sz
            p = (
                p[: self.fields_desc[0].sz]
                + struct.pack("!I", length)
                + p[position_after_length:]
            )
        return p + pay



class BMP(Packet):
    """
     Every BMP  message inherits from this class.
     """
    def guess_payload_class(self, payload):
        return BMPHeader


class_to_type = {}
for elem in BMPHeader.payload_guess:
    elem_dict, class_obj = elem
    if "type" not in elem_dict:
        continue
    class_to_type[class_obj] = elem_dict["type"]


def build_bmp(payload):
    if payload.__class__ in class_to_type:
        return BMPHeader(version=4, type=class_to_type[payload.__class__]) / payload
    raise Exception("Type not found")


bind_layers(TCP, BMP, dport=1790)
bind_layers(TCP, BMP, sport=1790)
bind_layers(BMPHeader, BMPRouteMonitoring, {"type": 0})
bind_layers(BMPHeader, BMPStats, {"type": 1})
bind_layers(BMPHeader, BMPPeerDown, {"type": 2})
bind_layers(BMPHeader, BMPPeerUp, {"type": 3})
bind_layers(BMPHeader, BMPInitiation, {"type": 4})
bind_layers(BMPHeader, BMPTermination, {"type": 5})
bind_layers(BMPHeader, BMPRouteMirroing, {"type": 6})

#!/usr/bin/env python

import sys
# import hashlib

# from thrift import Thrift
from thrift.transport import TSocket
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol
from thrift.protocol import TMultiplexedProtocol

from .bm_runtime.standard import Standard
from .bm_runtime.standard.ttypes import *

CUSTOM_CRC_CALCS = {}
CUSTOM_CRC_CALCS["calc"] = 16
# CUSTOM_CRC_CALCS['crc32_custom'] = 32


class UIn_Error(Exception):
    def __init__(self, info=""):
        self.info = info

    def __str__(self):
        return self.info


class UIn_ResourceError(UIn_Error):
    def __init__(self, res_type, name):
        self.res_type = res_type
        self.name = name

    def __str__(self):
        return "Invalid %s name (%s)" % (self.res_type, self.name)


# class UIn_MatchKeyError(UIn_Error):
#     def __init__(self, info=""):
#         self.info = info

#     def __str__(self):
#         return self.info


# class UIn_RuntimeDataError(UIn_Error):
#     def __init__(self, info=""):
#         self.info = info

#     def __str__(self):
#         return self.info


def hex_to_i16(h):
    x = int(h, 0)
    if x > 0xFFFF:
        raise UIn_Error("Integer cannot fit within 16 bits")
    if x > 0x7FFF:
        x -= 0x10000
    return x


# def i16_to_hex(h):
#     x = int(h)
#     if x & 0x8000:
#         x += 0x10000
#     return x


def hex_to_i32(h):
    x = int(h, 0)
    if x > 0xFFFFFFFF:
        raise UIn_Error("Integer cannot fit within 32 bits")
    if x > 0x7FFFFFFF:
        x -= 0x100000000
    return x


# def i32_to_hex(h):
#     x = int(h)
#     if x & 0x80000000:
#         x += 0x100000000
#     return x


def parse_bool(s):
    if s == "true" or s == "True":
        return True
    if s == "false" or s == "False":
        return False
    try:
        s = int(s, 0)
        return bool(s)
    except:
        pass
    raise UIn_Error("Invalid bool parameter")


# def hexstr(v):
#     if sys.version_info >= (3, 0):
#         # different byte processing in Python 3
#         return "".join([format(c, "02x") for c in v])
#     return "".join("{:02x}".format(ord(c)) for c in v)


def exactly_n_args(args, n):
    if len(args) != n:
        raise UIn_Error(f"Wrong number of args, expected {n} but got {len(args)}")


# def check_JSON_md5(client, json_src, out=sys.stdout):
#     with open(json_src, "r") as f:
#         m = hashlib.md5()
#         for L in f:
#             m.update(L)
#         md5sum = m.digest()

#     def my_print(s):
#         out.write(s)

#     try:
#         bm_md5sum = client.bm_get_config_md5()
#     except:
#         my_print("Error when requesting config md5 sum from switch\n")
#         sys.exit(1)

#     if md5sum != bm_md5sum:
#         my_print("**********\n")
#         my_print("WARNING: the JSON files loaded into the switch and the one ")
#         my_print("you just provided to this CLI don't have the same md5 sum. ")
#         my_print("Are you sure they describe the same program?\n")
#         bm_md5sum_str = "".join("{:02x}".format(ord(c)) for c in bm_md5sum)
#         md5sum_str = "".join("{:02x}".format(ord(c)) for c in md5sum)
#         my_print("{:<15}: {}\n".format("switch md5", bm_md5sum_str))
#         my_print("{:<15}: {}\n".format("CLI input md5", md5sum_str))
#         my_print("**********\n")


# def get_json_config(standard_client=None, json_path=None, out=sys.stdout):
#     def my_print(s):
#         out.write(s)

#     if json_path:
#         if standard_client is not None:
#             check_JSON_md5(standard_client, json_path)
#         with open(json_path, "r") as f:
#             return f.read()
#     else:
#         assert standard_client is not None
#         try:
#             my_print("Obtaining JSON from switch...\n")
#             json_cfg = standard_client.bm_get_config()
#             my_print("Done\n")
#         except:
#             my_print("Error when requesting JSON config from switch\n")
#             sys.exit(1)
#         return json_cfg


# services is [(service_name, client_class), ...]
def set_crc_parameters_common(client, line, crc_width=16):
    conversion_fn = {16: hex_to_i16, 32: hex_to_i32}[crc_width]
    config_type = {16: BmCrc16Config, 32: BmCrc32Config}[crc_width]
    thrift_fn = {
        16: client.bm_set_crc16_custom_parameters,
        32: client.bm_set_crc32_custom_parameters,
    }[crc_width]
    args = line.split()
    exactly_n_args(args, 6)
    name = args[0]
    if name not in CUSTOM_CRC_CALCS or CUSTOM_CRC_CALCS[name] != crc_width:
        raise UIn_ResourceError(f"crc{crc_width}_custom", name)
    config_args = [conversion_fn(a) for a in args[1:4]]
    config_args += [parse_bool(a) for a in args[4:6]]
    crc_config = config_type(*config_args)
    thrift_fn(0, name, crc_config)


def thrift_connect(thrift_ip, thrift_port, services, out=sys.stdout):
    def my_print(s):
        out.write(s)

    # Make socket
    transport = TSocket.TSocket(thrift_ip, thrift_port)
    # Buffering is critical. Raw sockets are very slow
    transport = TTransport.TBufferedTransport(transport)
    # Wrap in a protocol
    bprotocol = TBinaryProtocol.TBinaryProtocol(transport)

    clients = []

    for service_name, service_cls in services:
        if service_name is None:
            clients.append(None)
            continue
        protocol = TMultiplexedProtocol.TMultiplexedProtocol(bprotocol, service_name)
        client = service_cls(protocol)
        clients.append(client)

    # Connect!
    try:
        transport.open()
    except TTransport.TTransportException:
        my_print("Could not connect to thrift client on port {}\n".format(thrift_port))
        my_print("Make sure the switch is running ")
        my_print("and that you have the right port\n")
        sys.exit(1)
    
    # print(clients)

    return clients


def thrift_connect_standard(thrift_ip, thrift_port, out=sys.stdout):
    return thrift_connect(thrift_ip, thrift_port, [("standard", Standard.Client)], out)[
        0
    ]

def main():
    switch1 = thrift_connect_standard("0.0.0.0", 50002)
    set_crc_parameters_common(client=switch1, line="calc 0x003b 0x0 0x0 false false")
    # print(switch1.bm_get_config())


if __name__ == "__main__":
    main()

# -*- coding: latin-1 -*-
from __future__ import absolute_import, division

import nfc
import nfc.tag
import nfc.tag.tt3

import mock
import pytest
from pytest_mock import mocker  # noqa: F401

from Crypto.Cipher import AES, DES, DES3
from Crypto.Hash import CMAC

import struct
import logging
logging.basicConfig(level=logging.WARN)
logging_level = logging.getLogger().getEffectiveLevel()
logging.getLogger("nfc.tag").setLevel(logging_level)
logging.getLogger("nfc.tag.tt3").setLevel(logging_level)
logging.getLogger("nfc.tag.tt3_sony").setLevel(logging_level)


def HEX(s):
    return bytearray.fromhex(s)


@pytest.fixture()
def clf(mocker):  # noqa: F811
    clf = nfc.ContactlessFrontend()
    mocker.patch.object(clf, 'exchange', autospec=True)
    mocker.patch('os.urandom',
                 new=lambda x: struct.pack("{}B".format(x), *range(x)))
    return clf


###############################################################################
#
# FeliCa Standard
#
###############################################################################
felica_sample_1_responses = [
    HEX('0f 0d 0102030405060708 028092fe00'),
    HEX('12 01 0102030405060708 03014b024f4993ff'),
    HEX('0e 0b 0102030405060708 0000feff'),
    HEX('0c 0b 0102030405060708 ffff'),
    HEX('12 01 0102030405060708 03014b024f4993ff'),
    HEX('0e 0b 0102030405060708 0000feff'),
    HEX('0e 0b 0102030405060708 00101717'),
    HEX('0e 0b 0102030405060708 01101717'),
    HEX('0c 0b 0102030405060708 0810'),
    HEX('0c 0b 0102030405060708 0811'),
    HEX('0c 0b 0102030405060708 0a11'),
    HEX('0c 0b 0102030405060708 0b11'),
    HEX('0c 0b 0102030405060708 0812'),
    HEX('1d 07 0102030405060708 00000100011001900700004225098e00000011'),
    HEX('1d 07 0102030405060708 000001000061a80000c3500000c35000000000'),
    HEX('0c 07 0102030405060708 01a8'),
    HEX('0c 0b 0102030405060708 1013'),
    HEX('0c 0b 0102030405060708 1213'),
    HEX('0c 0b 0102030405060708 1713'),
    HEX('0c 0b 0102030405060708 0814'),
    HEX('1d 07 0102030405060708 0000019e0100004a0200000000000000000400'),
    HEX('0c 07 0102030405060708 01a8'),
    HEX('0c 0b 0102030405060708 0a14'),
    HEX('0c 0b 0102030405060708 0815'),
    HEX('0c 0b 0102030405060708 0a15'),
    HEX('0c 0b 0102030405060708 0816'),
    HEX('0c 0b 0102030405060708 0a16'),
    HEX('0c 0b 0102030405060708 0c17'),
    HEX('0c 0b 0102030405060708 0f17'),
    HEX('0c 0b 0102030405060708 ffff'),
    HEX('1d 07 0102030405060708 000001200000042e02ae410000024a0000019e'),
    HEX('1d 07 0102030405060708 000001020000032e02ab84000003e8000003e8'),
    HEX('1d 07 0102030405060708 000001200000020a98ac7d000001f400000000'),
    HEX('1d 07 0102030405060708 00000104000001099a9dad000001f4000001f4'),
    HEX('1d 07 0102030405060708 00000100060000000000000000000000000000'),
    HEX('1d 07 0102030405060708 00000100050000000000000000000000000000'),
    HEX('0c 07 0102030405060708 01a8'),
]

felica_sample_1_sys = 0x8092

felica_sample_1_dump = """
System 8092 (unknown)
Area 0000--FFFE
System FE00 (Common Area)
Area 0000--FFFE
  Area 1000--1717
    Area 1001--1717
      Random Service 64: write with key (0x1008)
      Random Service 68: write with key & read with key & read w/o key (0x1108 0x110A 0x110B)
       0000: 00 01 10 01 90 07 00 00 42 25 09 8e 00 00 00 11 |........B%......|
       0001: 00 00 61 a8 00 00 c3 50 00 00 c3 50 00 00 00 00 |..a....P...P....|
      Random Service 72: write with key (0x1208)
      Purse Service 76: direct with key & cashback with key & read w/o key (0x1310 0x1312 0x1317)
       0000: 9e 01 00 00 4a 02 00 00 00 00 00 00 00 00 04 00 |....J...........|
      Random Service 80: write with key & read with key (0x1408 0x140A)
      Random Service 84: write with key & read with key (0x1508 0x150A)
      Random Service 88: write with key & read with key (0x1608 0x160A)
      Cyclic Service 92: write with key & read w/o key (0x170C 0x170F)
       0000: 20 00 00 04 2e 02 ae 41 00 00 02 4a 00 00 01 9e | ......A...J....|
       0001: 02 00 00 03 2e 02 ab 84 00 00 03 e8 00 00 03 e8 |................|
       0002: 20 00 00 02 0a 98 ac 7d 00 00 01 f4 00 00 00 00 | ......}........|
       0003: 04 00 00 01 09 9a 9d ad 00 00 01 f4 00 00 01 f4 |................|
       0004: 00 06 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|
       0005: 00 05 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|
""".strip().splitlines()  # noqa: E501

felica_sample_2_responses = [
    HEX("11 0d 0102030405060708 030003fe0086a7"),
    HEX("12 01 0102030405060708 100b4b428485d0ff"),
    HEX("0e 0b 0102030405060708 0000feff"),
    HEX("0e 0b 0102030405060708 4000ff07"),
    HEX("0c 0b 0102030405060708 4800"),
    HEX("0c 0b 0102030405060708 4a00"),
    HEX("0c 0b 0102030405060708 8800"),
    HEX("0c 0b 0102030405060708 8b00"),
    HEX("0e 0b 0102030405060708 0008bf0f"),
    HEX("1d 07 0102030405060708 0000010000000000000000200000fc08000022"),
    HEX("0c 07 0102030405060708 01a8"),
    HEX("0c 0b 0102030405060708 1008"),
    HEX("0c 0b 0102030405060708 1208"),
    HEX("0c 0b 0102030405060708 1608"),
    HEX("0c 0b 0102030405060708 5008"),
    HEX("0c 0b 0102030405060708 5208"),
    HEX("0c 0b 0102030405060708 5608"),
    HEX("0c 0b 0102030405060708 9008"),
    HEX("0c 0b 0102030405060708 9208"),
    HEX("0c 0b 0102030405060708 9608"),
    HEX("0c 0b 0102030405060708 c808"),
    HEX("0c 0b 0102030405060708 ca08"),
    HEX("0c 0b 0102030405060708 0a09"),
    HEX("0c 0b 0102030405060708 0c09"),
    HEX("0c 0b 0102030405060708 0f09"),
    HEX("0e 0b 0102030405060708 c00fff7f"),
    HEX("1d 07 0102030405060708 000001c746000018d93d802928fc0800002200"),
    HEX("1d 07 0102030405060708 000001c746000018d8aba02927920900002100"),
    HEX("1d 07 0102030405060708 000001c746000018d88e002753280a00002000"),
    HEX("1d 07 0102030405060708 000001c746000018d73ee02752720b00001f00"),
    HEX("1d 07 0102030405060708 0000010802000018d701070000480d00001e00"),
    HEX("1d 07 0102030405060708 000001c846000018d72a43b195900100001d00"),
    HEX("1d 07 0102030405060708 000001c746000018d538a028a0120200001c00"),
    HEX("1d 07 0102030405060708 000001c746000017715200505a320500001b00"),
    HEX("1d 07 0102030405060708 00000116010002176e25070107260700001a00"),
    HEX("1d 07 0102030405060708 00000116010002176e01072507c60700001800"),
    HEX("1d 07 0102030405060708 00000108020000176e01070000660800001600"),
    HEX("1d 07 0102030405060708 0000011601000212e801020107960000001500"),
    HEX("1d 07 0102030405060708 0000011601000212e8250201022c0100001300"),
    HEX("1d 07 0102030405060708 0000011601000212e801072502cc0100001100"),
    HEX("1d 07 0102030405060708 0000011601000212e7010601074e0200000f00"),
    HEX("1d 07 0102030405060708 0000011601000212e701070106d00200000d00"),
    HEX("1d 07 0102030405060708 0000011601000212e625020107520300000b00"),
    HEX("1d 07 0102030405060708 0000011601000212e601072502d40300000900"),
    HEX("1d 07 0102030405060708 0000011601000212e325020107560400000700"),
    HEX("1d 07 0102030405060708 0000011601000212e301072502d80400000500"),
    HEX("0c 07 0102030405060708 01a8"),
    HEX("0e 0b 0102030405060708 0010bf17"),
    HEX("0c 0b 0102030405060708 0810"),
    HEX("0c 0b 0102030405060708 0a10"),
    HEX("0c 0b 0102030405060708 4810"),
    HEX("0c 0b 0102030405060708 4a10"),
    HEX("0c 0b 0102030405060708 8c10"),
    HEX("0c 0b 0102030405060708 8f10"),
    HEX("0c 0b 0102030405060708 c810"),
    HEX("1d 07 0102030405060708 000001200001071015176e2210a00000000000"),
    HEX("1d 07 0102030405060708 000001a00025075007176e2151000000000000"),
    HEX("1d 07 0102030405060708 000001200025075002176e1901a00000000000"),
    HEX("0c 07 0102030405060708 01a8"),
    HEX("0c 0b 0102030405060708 cb10"),
    HEX("0c 0b 0102030405060708 0811"),
    HEX("1d 07 0102030405060708 00000125070000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("0c 07 0102030405060708 01a8"),
    HEX("0c 0b 0102030405060708 0a11"),
    HEX("0c 0b 0102030405060708 4811"),
    HEX("0c 0b 0102030405060708 4a11"),
    HEX("0e 0b 0102030405060708 c017ff7f"),
    HEX("0e 0b 0102030405060708 00183f1a"),
    HEX("0c 0b 0102030405060708 0818"),
    HEX("0c 0b 0102030405060708 0a18"),
    HEX("0c 0b 0102030405060708 4818"),
    HEX("0c 0b 0102030405060708 4b18"),
    HEX("0c 0b 0102030405060708 c818"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("0c 07 0102030405060708 01a8"),
    HEX("0c 0b 0102030405060708 ca18"),
    HEX("0c 0b 0102030405060708 0819"),
    HEX("0c 0b 0102030405060708 0a19"),
    HEX("0c 0b 0102030405060708 4819"),
    HEX("0c 0b 0102030405060708 4b19"),
    HEX("0c 0b 0102030405060708 8819"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("0c 07 0102030405060708 01a8"),
    HEX("0c 0b 0102030405060708 8b19"),
    HEX("0e 0b 0102030405060708 00233f24"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("0c 07 0102030405060708 01a8"),
    HEX("0c 0b 0102030405060708 0823"),
    HEX("0c 0b 0102030405060708 0a23"),
    HEX("0c 0b 0102030405060708 4823"),
    HEX("0c 0b 0102030405060708 4b23"),
    HEX("0c 0b 0102030405060708 8823"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("0c 07 0102030405060708 01a8"),
    HEX("0c 0b 0102030405060708 8b23"),
    HEX("0c 0b 0102030405060708 c823"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("0c 07 0102030405060708 01a8"),
    HEX("0c 0b 0102030405060708 cb23"),
    HEX("0c 0b 0102030405060708 ffff"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("0c 07 0102030405060708 01a8"),
    HEX("12 01 0102030405060708 100b4b428485d0ff"),
    HEX("0e 0b 0102030405060708 0000feff"),
    HEX("0e 0b 0102030405060708 4039ff39"),
    HEX("0e 0b 0102030405060708 4139ff39"),
    HEX("0c 0b 0102030405060708 4839"),
    HEX("0c 0b 0102030405060708 4b39"),
    HEX("0c 0b 0102030405060708 8839"),
    HEX("1d 07 0102030405060708 00000148077739080000040100000000000000"),
    HEX("0c 07 0102030405060708 01a8"),
    HEX("0c 0b 0102030405060708 8b39"),
    HEX("0c 0b 0102030405060708 c939"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("0c 07 0102030405060708 01a8"),
    HEX("0c 0b 0102030405060708 ffff"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("0c 07 0102030405060708 01a8"),
    HEX("12 01 0102030405060708 100b4b428485d0ff"),
    HEX("0e 0b 0102030405060708 0000feff"),
    HEX("0e 0b 0102030405060708 40007f00"),
    HEX("0c 0b 0102030405060708 4800"),
    HEX("0c 0b 0102030405060708 4b00"),
    HEX("0e 0b 0102030405060708 8002bf02"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("0c 07 0102030405060708 01a8"),
    HEX("0c 0b 0102030405060708 8802"),
    HEX("0c 0b 0102030405060708 8b02"),
    HEX("0c 0b 0102030405060708 ffff"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 00000100000000000000000000000000000000"),
    HEX("0c 07 0102030405060708 01a8"),
]

felica_sample_2_sys = 0x0003

felica_sample_2_dump = """
System 0003 (Suica)
Area 0000--FFFE
  Area 0040--07FF
    Random Service 1: write with key & read with key (0x0048 0x004A)
    Random Service 2: write with key & read w/o key (0x0088 0x008B)
     0000: 00 00 00 00 00 00 00 00 20 00 00 fc 08 00 00 22 |........ ......"|
    Area 0800--0FBF
    Purse Service 32: direct with key & cashback with key & read with key (0x0810 0x0812 0x0816)
    Purse Service 33: direct with key & cashback with key & read with key (0x0850 0x0852 0x0856)
    Purse Service 34: direct with key & cashback with key & read with key (0x0890 0x0892 0x0896)
    Random Service 35: write with key & read with key (0x08C8 0x08CA)
    Random Service 36: read with key (0x090A)
    Cyclic Service 36: write with key & read w/o key (0x090C 0x090F)
     0000: c7 46 00 00 18 d9 3d 80 29 28 fc 08 00 00 22 00 |.F....=.)(....".|
     0001: c7 46 00 00 18 d8 ab a0 29 27 92 09 00 00 21 00 |.F......)'....!.|
     0002: c7 46 00 00 18 d8 8e 00 27 53 28 0a 00 00 20 00 |.F......'S(... .|
     0003: c7 46 00 00 18 d7 3e e0 27 52 72 0b 00 00 1f 00 |.F....>.'Rr.....|
     0004: 08 02 00 00 18 d7 01 07 00 00 48 0d 00 00 1e 00 |..........H.....|
     0005: c8 46 00 00 18 d7 2a 43 b1 95 90 01 00 00 1d 00 |.F....*C........|
     0006: c7 46 00 00 18 d5 38 a0 28 a0 12 02 00 00 1c 00 |.F....8.(.......|
     0007: c7 46 00 00 17 71 52 00 50 5a 32 05 00 00 1b 00 |.F...qR.PZ2.....|
     0008: 16 01 00 02 17 6e 25 07 01 07 26 07 00 00 1a 00 |.....n%...&.....|
     0009: 16 01 00 02 17 6e 01 07 25 07 c6 07 00 00 18 00 |.....n..%.......|
     000A: 08 02 00 00 17 6e 01 07 00 00 66 08 00 00 16 00 |.....n....f.....|
     000B: 16 01 00 02 12 e8 01 02 01 07 96 00 00 00 15 00 |................|
     000C: 16 01 00 02 12 e8 25 02 01 02 2c 01 00 00 13 00 |......%...,.....|
     000D: 16 01 00 02 12 e8 01 07 25 02 cc 01 00 00 11 00 |........%.......|
     000E: 16 01 00 02 12 e7 01 06 01 07 4e 02 00 00 0f 00 |..........N.....|
     000F: 16 01 00 02 12 e7 01 07 01 06 d0 02 00 00 0d 00 |................|
     0010: 16 01 00 02 12 e6 25 02 01 07 52 03 00 00 0b 00 |......%...R.....|
     0011: 16 01 00 02 12 e6 01 07 25 02 d4 03 00 00 09 00 |........%.......|
     0012: 16 01 00 02 12 e3 25 02 01 07 56 04 00 00 07 00 |......%...V.....|
     0013: 16 01 00 02 12 e3 01 07 25 02 d8 04 00 00 05 00 |........%.......|
    Area 0FC0--7FFF
    Area 1000--17BF
      Random Service 64: write with key & read with key (0x1008 0x100A)
      Random Service 65: write with key & read with key (0x1048 0x104A)
      Cyclic Service 66: write with key & read w/o key (0x108C 0x108F)
       0000: 20 00 01 07 10 15 17 6e 22 10 a0 00 00 00 00 00 | ......n".......|
       0001: a0 00 25 07 50 07 17 6e 21 51 00 00 00 00 00 00 |..%.P..n!Q......|
       0002: 20 00 25 07 50 02 17 6e 19 01 a0 00 00 00 00 00 | .%.P..n........|
      Random Service 67: write with key & read w/o key (0x10C8 0x10CB)
       0000: 25 07 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |%...............|
       0001: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|
      Random Service 68: write with key & read with key (0x1108 0x110A)
      Random Service 69: write with key & read with key (0x1148 0x114A)
      Area 17C0--7FFF
      Area 1800--1A3F
        Random Service 96: write with key & read with key (0x1808 0x180A)
        Random Service 97: write with key & read w/o key (0x1848 0x184B)
         0000: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|
         *     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|
         0023: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|
        Random Service 99: write with key & read with key (0x18C8 0x18CA)
        Random Service 100: write with key & read with key (0x1908 0x190A)
        Random Service 101: write with key & read w/o key (0x1948 0x194B)
         0000: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|
         *     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|
         000F: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|
        Random Service 102: write with key & read w/o key (0x1988 0x198B)
         0000: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|
         *     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|
         0002: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|
        Area 2300--243F
        Random Service 140: write with key & read with key (0x2308 0x230A)
        Random Service 141: write with key & read w/o key (0x2348 0x234B)
         0000: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|
         *     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|
         0003: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|
        Random Service 142: write with key & read w/o key (0x2388 0x238B)
         0000: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|
         *     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|
         000F: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|
        Random Service 143: write with key & read w/o key (0x23C8 0x23CB)
         0000: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|
         *     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|
         0003: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|
System FE00 (Common Area)
Area 0000--FFFE
  Area 3940--39FF
    Area 3941--39FF
      Random Service 229: write with key & read w/o key (0x3948 0x394B)
       0000: 48 07 77 39 08 00 00 04 01 00 00 00 00 00 00 00 |H.w9............|
      Random Service 230: write with key & read w/o key (0x3988 0x398B)
       0000: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|
       *     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|
       000F: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|
      Random Service 231: write w/o key (0x39C9)
       0000: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|
       *     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|
       0005: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|
System 86A7 (unknown)
Area 0000--FFFE
  Area 0040--007F
    Random Service 1: write with key & read w/o key (0x0048 0x004B)
     0000: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|
     *     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|
     0004: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|
    Area 0280--02BF
    Random Service 10: write with key & read w/o key (0x0288 0x028B)
     0000: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|
     *     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|
     0004: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|
""".strip().splitlines()  # noqa: E501


felica_sample_3_responses = [
    nfc.clf.TimeoutError, nfc.clf.TimeoutError, nfc.clf.TimeoutError,
    HEX("1d 07 0102030405060708 0000 01 100b0a009300000000000100000000b9"),
    HEX("1d 07 0102030405060708 0000 01 00000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 0000 01 00000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 0000 01 00000000000000000000000000000000"),
    HEX("1d 07 0102030405060708 0000 01 00000000000000000000000000000000"),
    nfc.clf.TimeoutError, nfc.clf.TimeoutError, nfc.clf.TimeoutError,
]

felica_sample_3_sys = 0x12FC

felica_sample_3_dump = [
    "0000: 10 0b 0a 00 93 00 00 00 00 00 01 00 00 00 00 b9 |................|",
    "0001: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|",
    "*     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|",
    "0004: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|",
]

felica_sample_4_responses = [
    nfc.clf.TimeoutError, nfc.clf.TimeoutError, nfc.clf.TimeoutError,
]

felica_sample_4_sys = 0x0000

felica_sample_4_dump = [
    "unable to create a memory dump",
]


class TestFelicaStandard:
    @pytest.fixture()
    def target(self):
        target = nfc.clf.RemoteTarget("212F")
        target.sensf_res = HEX("01 0102030405060708 0000FFFFFFFFFFFF 0000")
        return target

    @pytest.fixture()
    def tag(self, clf, target):
        tag = nfc.tag.activate(clf, target)
        assert isinstance(tag, nfc.tag.tt3_sony.FelicaStandard)
        return tag

    @pytest.mark.parametrize("ic_code, product", [
        ('00', "FeliCa Standard (RC-S830)"),
        ('01', "FeliCa Standard (RC-S915)"),
        ('02', "FeliCa Standard (RC-S919)"),
        ('08', "FeliCa Standard (RC-S952)"),
        ('09', "FeliCa Standard (RC-S953)"),
        ('0B', "FeliCa Standard (RC-S???)"),
        ('0C', "FeliCa Standard (RC-S954)"),
        ('0D', "FeliCa Standard (RC-S960)"),
        ('20', "FeliCa Standard (RC-S962)"),
        ('32', "FeliCa Standard (RC-SA00/1)"),
        ('35', "FeliCa Standard (RC-SA00/2)"),
    ])
    def test_init(self, target, ic_code, product):
        target.sensf_res[10] = HEX(ic_code)[0]
        tag = nfc.tag.activate(clf, target)
        assert isinstance(tag, nfc.tag.tt3_sony.FelicaStandard)
        assert tag.product == product

    @pytest.mark.parametrize("responses, dump, system_code", [
        (felica_sample_1_responses, felica_sample_1_dump, felica_sample_1_sys),
        (felica_sample_2_responses, felica_sample_2_dump, felica_sample_2_sys),
        (felica_sample_3_responses, felica_sample_3_dump, felica_sample_3_sys),
        (felica_sample_4_responses, felica_sample_4_dump, felica_sample_4_sys),
    ])
    def test_dump(self, tag, responses, dump, system_code):
        tag.sys = system_code
        tag.clf.exchange.side_effect = responses
        assert tag.dump() == dump

    @pytest.mark.parametrize("mode, result", [
        ('00', True), ('01', True), ('02', True), ('03', True),
        ('04', False), ('FF', False),
    ])
    def test_is_present_request_response(self, tag, mode, result):
        cmd = HEX('0a 04 0102030405060708')
        rsp = HEX('0b 05 0102030405060708') + HEX(mode)
        tag.clf.exchange.return_value = rsp
        assert tag.is_present is result
        tag.clf.exchange.assert_called_once_with(cmd, 0.309248)

    def test_is_present_polling_command(self, tag):
        tag.clf.exchange.side_effect = [
            nfc.clf.TimeoutError, nfc.clf.TimeoutError, nfc.clf.TimeoutError,
            HEX("12 01 0102030405060708 0000FFFFFFFFFFFF"),
        ]
        assert tag.is_present is True
        assert tag.clf.exchange.mock_calls == [
            mock.call(HEX('0a 04 0102030405060708'), 0.309248),
            mock.call(HEX('0a 04 0102030405060708'), 0.309248),
            mock.call(HEX('0a 04 0102030405060708'), 0.309248),
            mock.call(HEX('06 00 0000 0000'), 0.003625),
        ]

    def test_request_service(self, tag):
        sc_1 = nfc.tag.tt3.ServiceCode(0, 9)
        sc_2 = nfc.tag.tt3.ServiceCode(1, 9)
        cmd = HEX('0f 02 0102030405060708 02 0900 4900')
        rsp = HEX('0f 03 0102030405060708 02 0100 1100')
        tag.clf.exchange.return_value = rsp
        assert tag.request_service([sc_1, sc_2]) == [0x0001, 0x0011]
        tag.clf.exchange.assert_called_once_with(cmd, 0.46387200000000006)

        tag.clf.exchange.reset_mock()
        rsp = HEX('0e 03 0102030405060708 01 0000 00')
        tag.clf.exchange.return_value = rsp
        with pytest.raises(nfc.tag.tt3.Type3TagCommandError) as excinfo:
            tag.request_service([sc_1, sc_2])
        assert excinfo.value.errno == nfc.tag.tt3.DATA_SIZE_ERROR
        tag.clf.exchange.assert_called_once_with(cmd, 0.46387200000000006)

    def test_request_response(self, tag):
        cmd = HEX('0a 04 0102030405060708')
        rsp = HEX('0b 05 0102030405060708 00')
        tag.clf.exchange.return_value = rsp
        assert tag.request_response() == 0
        tag.clf.exchange.assert_called_once_with(cmd, 0.309248)

        tag.clf.exchange.reset_mock()
        rsp = HEX('0a 05 0102030405060708')
        tag.clf.exchange.return_value = rsp
        with pytest.raises(nfc.tag.tt3.Type3TagCommandError) as excinfo:
            tag.request_response()
        assert excinfo.value.errno == nfc.tag.tt3.DATA_SIZE_ERROR
        tag.clf.exchange.assert_called_once_with(cmd, 0.309248)

    def test_search_service_code(self, tag):
        cmd = HEX('0c 0a 0102030405060708 0000')
        rsp = HEX('0e 0b 0102030405060708 0000 FEFF')
        tag.clf.exchange.return_value = rsp
        assert tag.search_service_code(0) == (0x0000, 0xFFFE)
        tag.clf.exchange.assert_called_once_with(cmd, 0.154624)

        tag.clf.exchange.reset_mock()
        cmd = HEX('0c 0a 0102030405060708 0100')
        rsp = HEX('0c 0b 0102030405060708 0900')
        tag.clf.exchange.return_value = rsp
        assert tag.search_service_code(1) == (0x0009,)
        tag.clf.exchange.assert_called_once_with(cmd, 0.154624)

        tag.clf.exchange.reset_mock()
        cmd = HEX('0c 0a 0102030405060708 0010')
        rsp = HEX('0c 0b 0102030405060708 ffff')
        tag.clf.exchange.return_value = rsp
        assert tag.search_service_code(0x1000) is None
        tag.clf.exchange.assert_called_once_with(cmd, 0.154624)

    def test_request_system_code(self, tag):
        cmd = HEX('0a 0c 0102030405060708')
        rsp = HEX('0f 0d 0102030405060708 02 0000 12fc')
        tag.clf.exchange.return_value = rsp
        assert tag.request_system_code() == [0x0000, 0x12fc]
        tag.clf.exchange.assert_called_once_with(cmd, 0.154624)

        tag.clf.exchange.reset_mock()
        rsp = HEX('0f 0d 0102030405060708 03 0000 12fc')
        tag.clf.exchange.return_value = rsp
        with pytest.raises(nfc.tag.tt3.Type3TagCommandError) as excinfo:
            tag.request_system_code()
        assert excinfo.value.errno == nfc.tag.tt3.DATA_SIZE_ERROR
        tag.clf.exchange.assert_called_once_with(cmd, 0.154624)


###############################################################################
#
# FeliCa Standard proprietary commands
#
# The crypto below is deliberately written against PyCryptodome directly
# instead of reusing the FelicaStandard helpers, so that the expected values
# are derived independently of the code under test. The *_card_* functions
# play the card side of a protocol run.
#
###############################################################################

# Every PMm timing byte of the test target is FFh, i.e. a=7, b=7, e=3. The
# resulting timeout is 302us * ((b + 1) * units + a + 1) * 4**e.
STD_TIMEOUT = 0.154624               # commands without unit scaling
STD_TIMEOUT_1 = 0.309248             # one unit
STD_TIMEOUT_2 = 0.46387200000000006  # two units

STD_IDM = HEX('0102030405060708')


def reset_exchange(tag):
    """Forget recorded calls and any queued responses."""
    tag.clf.exchange.side_effect = None
    tag.clf.exchange.return_value = None
    tag.clf.exchange.reset_mock()


def xorbytes(a, b):
    return bytearray([x ^ y for x, y in zip(bytearray(a), bytearray(b))])


def pad8(data):
    """Pad to a multiple of 8 byte, the way the FeliCa secure packet does."""
    data = bytearray(data)
    if len(data) % 8:
        data.extend([8 - len(data) % 8] * (8 - len(data) % 8))
    return data


def des_ecb_encrypt(data, key):
    return bytearray(DES.new(bytes(key), DES.MODE_ECB).encrypt(bytes(data)))


def des_ecb_decrypt(data, key):
    return bytearray(DES.new(bytes(key), DES.MODE_ECB).decrypt(bytes(data)))


def des3_encrypt(data, key1, key2):
    key = bytes(key1) + bytes(key2) + bytes(key1)
    return bytearray(DES3.new(key, DES3.MODE_ECB).encrypt(bytes(data)))


def des3_decrypt(data, key1, key2):
    key = bytes(key1) + bytes(key2) + bytes(key1)
    return bytearray(DES3.new(key, DES3.MODE_ECB).decrypt(bytes(data)))


def des_cbc_encrypt(data, key):
    cipher = DES.new(bytes(key), DES.MODE_CBC, iv=b'\0' * 8)
    return bytearray(cipher.encrypt(bytes(data)))


def des_cbc_decrypt(data, key):
    cipher = DES.new(bytes(key), DES.MODE_CBC, iv=b'\0' * 8)
    return bytearray(cipher.decrypt(bytes(data)))


def aes_ecb_encrypt(data, key):
    return bytearray(AES.new(bytes(key), AES.MODE_ECB).encrypt(bytes(data)))


def aes_ecb_decrypt(data, key):
    return bytearray(AES.new(bytes(key), AES.MODE_ECB).decrypt(bytes(data)))


def des_packet_mac(code, payload):
    """Chained single DES MAC over the 8 byte blocks of a secure packet."""
    mac = bytearray(8)
    mac[0] = (2 + len(payload) + 8) & 0xFF
    mac[1] = code
    for i in range(0, len(payload), 8):
        mac = des_ecb_encrypt(mac, payload[i:i+8])
    return mac


def des_secure_packet(code, transaction_number, transaction_id, payload, key):
    """Build an encrypted DES secure messaging packet."""
    body = pad8(struct.pack("<H", transaction_number)
                + bytearray(transaction_id) + bytearray(payload))
    return des_cbc_encrypt(body + des_packet_mac(code, body), key)


def des_session_keys(idm, group_service_key, user_service_key):
    key_l = xorbytes(group_service_key, idm)
    alpha = des_ecb_encrypt(user_service_key, key_l)
    beta = des_ecb_encrypt(key_l, alpha)
    return key_l, alpha, beta


def aes_v2_iv(frame_length, code, counter_bytes, transaction_id, challenge_3c):
    iv = bytearray(16)
    iv[0] = 0x01
    iv[1] = frame_length & 0xFF
    iv[2] = code
    iv[3:5] = bytearray(counter_bytes)
    iv[5:11] = bytearray(transaction_id)
    iv[11:14] = bytearray(challenge_3c)[1:4]
    return iv


def aes_v2_mac(iv, payload, mac_key):
    b0 = bytearray(16)
    b0[0] = 0x19
    b0[1:14] = iv[1:14]
    b0[14:16] = struct.pack(">H", len(payload))
    cmac = CMAC.new(bytes(mac_key), ciphermod=AES)
    cmac.update(bytes(b0))
    cmac.update(bytes(payload))
    return bytearray(cmac.digest()[:8])


def aes_v2_crypt(encryption_key, iv, payload, mac):
    stream = AES.new(bytes(encryption_key), AES.MODE_OFB, iv=bytes(iv))
    payload_out = bytearray(stream.encrypt(bytes(payload)))
    aligned = ((len(payload) + 15) // 16) * 16
    if aligned > len(payload):
        stream.encrypt(b'\0' * (aligned - len(payload)))
    return payload_out, bytearray(stream.encrypt(bytes(mac)))


def aes_v2_secure_packet(code, transaction_number, transaction_id,
                         challenge_3c, encryption_key, mac_key, payload):
    """Build an encrypted AES-128 (v2) secure messaging packet."""
    counter_bytes = struct.pack("<H", transaction_number)
    frame_length = 2 + (2 + len(payload) + 8)
    iv = aes_v2_iv(frame_length, code, counter_bytes, transaction_id,
                   challenge_3c)
    mac = aes_v2_mac(iv, payload, mac_key)
    cipher_payload, cipher_mac = aes_v2_crypt(encryption_key, iv, payload, mac)
    return bytearray(counter_bytes) + cipher_payload + cipher_mac


def aes_v2_context_block(prefix, idm):
    block = bytearray(16)
    block[0:2] = bytearray(prefix)
    block[6:14] = bytearray(idm)
    block[14:16] = b'\x01\x00'
    return block


class TestFelicaStandardCommands:
    """FeliCa Standard proprietary command set."""

    @pytest.fixture()
    def target(self):
        target = nfc.clf.RemoteTarget("212F")
        target.sensf_res = HEX("01 0102030405060708 0000FFFFFFFFFFFF 0000")
        return target

    @pytest.fixture()
    def tag(self, clf, target):
        tag = nfc.tag.activate(clf, target)
        assert isinstance(tag, nfc.tag.tt3_sony.FelicaStandard)
        return tag

    #
    # card information and node inspection
    #

    def test_request_block_information(self, tag):
        cmd = HEX('0f 0e 0102030405060708 02 0000 0100')
        rsp = HEX('0f 0f 0102030405060708 02 0a00 1400')
        tag.clf.exchange.return_value = rsp
        assert tag.request_block_information([0x0000, 0x0001]) == [10, 20]
        tag.clf.exchange.assert_called_once_with(cmd, STD_TIMEOUT_2)

    def test_request_block_information_short_response(self, tag):
        tag.clf.exchange.return_value = \
            HEX('0d 0f 0102030405060708 02 0a00')
        with pytest.raises(nfc.tag.tt3.Type3TagCommandError) as excinfo:
            tag.request_block_information([0x0000, 0x0001])
        assert excinfo.value.errno == nfc.tag.tt3.DATA_SIZE_ERROR

    def test_request_block_information_ex(self, tag):
        cmd = HEX('0d 1e 0102030405060708 01 0900')
        rsp = HEX('11 1f 0102030405060708 0000 01 0a00 0500')
        tag.clf.exchange.return_value = rsp
        assert tag.request_block_information_ex([0x0009]) == ([10], [5])
        tag.clf.exchange.assert_called_once_with(cmd, STD_TIMEOUT_1)

    def test_request_block_information_ex_status_error(self, tag):
        tag.clf.exchange.return_value = \
            HEX('0c 1f 0102030405060708 ffa1')
        with pytest.raises(nfc.tag.tt3.Type3TagCommandError) as excinfo:
            tag.request_block_information_ex([0x0009])
        assert excinfo.value.errno == 0xFFA1

    def test_request_code_list(self, tag):
        cmd = HEX('0e 1a 0102030405060708 0000 0000')
        rsp = HEX('15 1b 0102030405060708 0000 01 01 0010 1717 01 0810')
        tag.clf.exchange.return_value = rsp
        assert tag.request_code_list(0x0000, 0) == \
            (True, [(0x1000, 0x1717)], [0x1008])
        tag.clf.exchange.assert_called_once_with(cmd, STD_TIMEOUT)

    def test_request_code_list_without_entries(self, tag):
        rsp = HEX('0f 1b 0102030405060708 0000 00 00 00')
        tag.clf.exchange.return_value = rsp
        assert tag.request_code_list(0x1000, 1) == (False, [], [])

    def test_set_parameter(self, tag):
        cmd = HEX('12 20 0102030405060708 00000000 01 00 0000')
        rsp = HEX('0c 21 0102030405060708 0000')
        tag.clf.exchange.return_value = rsp
        assert tag.set_parameter(1, 0) is None
        tag.clf.exchange.assert_called_once_with(cmd, STD_TIMEOUT)

    def test_set_parameter_rejected(self, tag):
        tag.clf.exchange.return_value = \
            HEX('0c 21 0102030405060708 ffb2')
        with pytest.raises(nfc.tag.tt3.Type3TagCommandError) as excinfo:
            tag.set_parameter(1, 0)
        assert excinfo.value.errno == 0xFFB2

    def test_set_parameter_status_flag2_warning(self, tag):
        # Status flag 1 is the sole authority on success, so a warning in
        # status flag 2 does not turn a completed command into a failure.
        tag.clf.exchange.return_value = \
            HEX('0c 21 0102030405060708 0071')
        assert tag.set_parameter(1, 0) is None

    def test_get_container_issue_information(self, tag):
        cmd = HEX('0c 22 0102030405060708 0000')
        rsp = HEX('1a 23 0102030405060708'
                  '0102030405 060708090a0b0c0d0e0f10')
        tag.clf.exchange.return_value = rsp
        assert tag.get_container_issue_information() == {
            "format_version_carrier_information": HEX('0102030405'),
            "mobile_phone_model_information": HEX('060708090a0b0c0d0e0f10'),
        }
        tag.clf.exchange.assert_called_once_with(cmd, STD_TIMEOUT)

    def test_get_container_property(self, tag):
        cmd = HEX('04 2e 0100')
        rsp = HEX('06 2f 01020304')
        tag.clf.exchange.return_value = rsp
        assert tag.get_container_property(1) == HEX('01020304')
        tag.clf.exchange.assert_called_once_with(cmd, STD_TIMEOUT)

    def test_get_container_id(self, tag):
        cmd = HEX('04 70 0000')
        rsp = HEX('0a 71 1122334455667788')
        tag.clf.exchange.return_value = rsp
        assert tag.get_container_id() == HEX('1122334455667788')
        tag.clf.exchange.assert_called_once_with(cmd, STD_TIMEOUT)

    def test_get_container_id_wrong_length(self, tag):
        tag.clf.exchange.return_value = HEX('09 71 11223344556677')
        with pytest.raises(nfc.tag.tt3.Type3TagCommandError) as excinfo:
            tag.get_container_id()
        assert excinfo.value.errno == nfc.tag.tt3.DATA_SIZE_ERROR

    def test_get_system_status(self, tag):
        cmd = HEX('0c 38 0102030405060708 0000')
        rsp = HEX('10 39 0102030405060708 0000 01 02 abcd')
        tag.clf.exchange.return_value = rsp
        assert tag.get_system_status() == (1, HEX('abcd'))
        tag.clf.exchange.assert_called_once_with(cmd, STD_TIMEOUT)

    def test_request_product_information(self, tag):
        cmd = HEX('0a 3a 0102030405060708')
        rsp = HEX('11 3b 0102030405060708 0000 04 01020304')
        tag.clf.exchange.return_value = rsp
        assert tag.request_product_information() == HEX('01020304')
        tag.clf.exchange.assert_called_once_with(cmd, STD_TIMEOUT)

    def test_request_specification_version(self, tag):
        cmd = HEX('0c 3c 0102030405060708 0000')
        rsp = HEX('12 3d 0102030405060708 0000 00 21 01 01 43 02')
        tag.clf.exchange.return_value = rsp
        version = tag.request_specification_version()
        assert version.format_version == 0x00
        assert version.basic_version == {"major": 1, "minor": 2, "patch": 1}
        assert version.option_versions == \
            [{"major": 2, "minor": 4, "patch": 3}]
        assert version.des_option_version == \
            {"major": 2, "minor": 4, "patch": 3}
        assert version.special_option_version is None
        assert version.random_id_option_version is None
        tag.clf.exchange.assert_called_once_with(cmd, STD_TIMEOUT)

    def test_request_specification_version_unsupported(self, tag):
        tag.clf.exchange.return_value = \
            HEX('0c 3d 0102030405060708 0000')
        assert tag.request_specification_version() is None

    def test_reset_mode(self, tag):
        cmd = HEX('0c 3e 0102030405060708 0000')
        rsp = HEX('0c 3f 0102030405060708 0000')
        tag.clf.exchange.return_value = rsp
        assert tag.reset_mode() is None
        tag.clf.exchange.assert_called_once_with(cmd, STD_TIMEOUT)

    def test_get_area_information(self, tag):
        cmd = HEX('0c 24 0102030405060708 0010')
        rsp = HEX('10 25 0102030405060708 0000 0010 1717')
        tag.clf.exchange.return_value = rsp
        assert tag.get_area_information(0x1000) == (0x1000, HEX('1717'))
        tag.clf.exchange.assert_called_once_with(cmd, STD_TIMEOUT)

    def test_get_node_property_purse_service(self, tag):
        cmd = HEX('0e 28 0102030405060708 00 01 0810')
        rsp = HEX('17 29 0102030405060708 0000 01'
                  '01 e8030000 00000000 05')
        tag.clf.exchange.return_value = rsp
        assert tag.get_node_property(0x00, [0x1008]) == [{
            "enabled": True,
            "upper_limit": 1000,
            "lower_limit": 0,
            "generation_number": 5,
        }]
        tag.clf.exchange.assert_called_once_with(cmd, STD_TIMEOUT_1)

    def test_get_node_property_mac_communication(self, tag):
        cmd = HEX('0e 28 0102030405060708 01 01 0810')
        rsp = HEX('0e 29 0102030405060708 0000 01 01')
        tag.clf.exchange.return_value = rsp
        assert tag.get_node_property(0x01, [0x1008]) == [{"enabled": True}]
        tag.clf.exchange.assert_called_once_with(cmd, STD_TIMEOUT_1)

    def test_get_node_property_node_count_mismatch(self, tag):
        tag.clf.exchange.return_value = \
            HEX('0e 29 0102030405060708 0000 02 01')
        with pytest.raises(nfc.tag.tt3.Type3TagCommandError) as excinfo:
            tag.get_node_property(0x01, [0x1008])
        assert excinfo.value.errno == nfc.tag.tt3.DATA_SIZE_ERROR

    @pytest.mark.parametrize("rsp_hex, expected", [
        # an unknown property type is decoded from the response layout
        ('17 29 0102030405060708 0000 01 01 e8030000 00000000 05',
         [{"enabled": True, "upper_limit": 1000, "lower_limit": 0,
           "generation_number": 5}]),
        ('0e 29 0102030405060708 0000 01 01', [{"enabled": True}]),
    ])
    def test_get_node_property_unknown_type(self, tag, rsp_hex, expected):
        tag.clf.exchange.return_value = HEX(rsp_hex)
        assert tag.get_node_property(0x02, [0x1008]) == expected

    def test_get_node_property_unknown_type_bad_length(self, tag):
        tag.clf.exchange.return_value = \
            HEX('10 29 0102030405060708 0000 01 010203')
        with pytest.raises(nfc.tag.tt3.Type3TagCommandError) as excinfo:
            tag.get_node_property(0x02, [0x1008])
        assert excinfo.value.errno == nfc.tag.tt3.DATA_SIZE_ERROR

    def test_request_service_v2_node_count_mismatch(self, tag):
        sc = nfc.tag.tt3.ServiceCode(0, 9)
        tag.clf.exchange.return_value = \
            HEX('10 33 0102030405060708 0000 00 02 0100')
        with pytest.raises(nfc.tag.tt3.Type3TagCommandError) as excinfo:
            tag.request_service_v2([sc])
        assert excinfo.value.errno == nfc.tag.tt3.DATA_SIZE_ERROR

    def test_request_service_v2_single_key(self, tag):
        sc = nfc.tag.tt3.ServiceCode(0, 9)
        cmd = HEX('0d 32 0102030405060708 01 0900')
        rsp = HEX('10 33 0102030405060708 0000 00 01 0100')
        tag.clf.exchange.return_value = rsp
        assert tag.request_service_v2([sc]) == (0x00, [1])
        tag.clf.exchange.assert_called_once_with(cmd, STD_TIMEOUT_1)

    @pytest.mark.parametrize("crypto_id", ['41', '43'])
    def test_request_service_v2_dual_keys(self, tag, crypto_id):
        sc = nfc.tag.tt3.ServiceCode(0, 9)
        cmd = HEX('0d 32 0102030405060708 01 0900')
        rsp = HEX('12 33 0102030405060708 0000') + HEX(crypto_id) \
            + HEX('01 0200 0300')
        tag.clf.exchange.return_value = rsp
        assert tag.request_service_v2([sc]) == (HEX(crypto_id)[0], [(2, 3)])
        tag.clf.exchange.assert_called_once_with(cmd, STD_TIMEOUT_1)

    #
    # protocol limits on list arguments
    #

    @pytest.mark.parametrize("call, message", [
        (lambda tag, n: tag.request_service(
            [nfc.tag.tt3.ServiceCode(0, 9)] * n),
         "service_list must contain between 1 and 32 entries"),
        (lambda tag, n: tag.request_service_v2(
            [nfc.tag.tt3.ServiceCode(0, 9)] * n),
         "service_list must contain between 1 and 32 entries"),
        (lambda tag, n: tag.request_block_information([0x1008] * n),
         "node_code_list must contain between 1 and 32 entries"),
        (lambda tag, n: tag.request_block_information_ex([0x1008] * n),
         "node_code_list must contain between 1 and 32 entries"),
    ])
    @pytest.mark.parametrize("count", [0, 33])
    def test_list_length_limits(self, tag, call, message, count):
        with pytest.raises(ValueError) as excinfo:
            call(tag, count)
        assert str(excinfo.value) == message
        assert tag.clf.exchange.mock_calls == []

    @pytest.mark.parametrize("count", [0, 17])
    def test_get_node_property_list_length_limit(self, tag, count):
        with pytest.raises(ValueError) as excinfo:
            tag.get_node_property(0x01, [0x1008] * count)
        assert str(excinfo.value) == \
            "node_code_list must contain between 1 and 16 entries"
        assert tag.clf.exchange.mock_calls == []

    @pytest.mark.parametrize("count", [0, 256])
    def test_secure_block_list_length_limit(self, tag, count):
        self.des_authenticate(tag)
        reset_exchange(tag)
        block_list = [nfc.tag.tt3.BlockCode(0)] * count
        with pytest.raises(ValueError) as excinfo:
            tag.read(block_list)
        assert str(excinfo.value) == \
            "block_list must contain between 1 and 14 entries"
        with pytest.raises(ValueError) as excinfo:
            tag.write(block_list, bytearray(16 * count))
        assert str(excinfo.value) == \
            "block_list must contain between 1 and 255 entries"
        assert tag.clf.exchange.mock_calls == []

    def test_secure_read_block_count_limits(self, tag):
        # A secure read is bounded by its response, and the DES scheme
        # loses one block to the PKCS#7 padding its response carries.
        assert nfc.tag.tt3_sony.FelicaStandard \
            .MAX_SECURE_READ_BLOCK_COUNT == 14
        assert nfc.tag.tt3_sony.FelicaStandard \
            .MAX_SECURE_READ_V2_BLOCK_COUNT == 15

        self.des_authenticate(tag)
        reset_exchange(tag)
        with pytest.raises(ValueError) as excinfo:
            tag.read([nfc.tag.tt3.BlockCode(0)] * 15)
        assert str(excinfo.value) == \
            "block_list must contain between 1 and 14 entries"
        with pytest.raises(ValueError) as excinfo:
            tag.read_v2([nfc.tag.tt3.BlockCode(0)] * 16)
        assert str(excinfo.value) == \
            "block_list must contain between 1 and 15 entries"
        assert tag.clf.exchange.mock_calls == []

    def test_secure_read_block_count_limits_fit_a_packet(self, tag):
        # The limits are what a 255 byte response packet holds, so the
        # maximum block count must frame and one more must not.
        for blocks, padded in ((14, True), (15, False)):
            # LEN + response code + E(txn + txid + SF1 + SF2 + n + 16n)
            # padded to whole DES blocks + MAC
            payload = 2 + 6 + 3 + blocks * 16
            length = 2 + (payload // 8 + 1) * 8 + 8
            assert (length <= 255) is padded

        for blocks, fits in ((15, True), (16, False)):
            # LEN + response code + counter + SF1 + SF2 + n + 16n + MAC
            length = 2 + 2 + 3 + blocks * 16 + 8
            assert (length <= 255) is fits

    def test_authentication1_too_many_nodes(self, tag):
        with pytest.raises(ValueError) as excinfo:
            tag.authentication1([0x0000] * 33, [], bytearray(8))
        assert str(excinfo.value) == "too many areas for authentication1"

        with pytest.raises(ValueError) as excinfo:
            tag.authentication1(
                [], [nfc.tag.tt3.ServiceCode(0, 9)] * 33, bytearray(8))
        assert str(excinfo.value) == "too many services for authentication1"
        assert tag.clf.exchange.mock_calls == []

    def test_authentication1_v2_too_many_nodes(self, tag):
        with pytest.raises(ValueError) as excinfo:
            tag.authentication1_v2(0x00, [0x1008] * 33, bytearray(16))
        assert str(excinfo.value) == "too many nodes for authentication1 v2"
        assert tag.clf.exchange.mock_calls == []

    def test_request_specification_version_bad_format_version(self, tag):
        tag.clf.exchange.return_value = \
            HEX('12 3d 0102030405060708 0000 01 21 01 01 43 02')
        with pytest.raises(nfc.tag.tt3.Type3TagCommandError) as excinfo:
            tag.request_specification_version()
        assert excinfo.value.errno == nfc.tag.PROTOCOL_ERROR

    #
    # secure packet MAC verification
    #

    @pytest.mark.parametrize("tail", [
        HEX('ffffffffffff'), HEX('000000000001'), HEX('010000000000'),
    ])
    def test_packet_mac_rejects_forged_reserved_tail(self, tail):
        """The full 8 byte MAC pre-image must be verified, not just 2 byte.

        A genuine MAC recovers ``[length, code, 0, 0, 0, 0, 0, 0]``. Checking
        only length and code would cut the forgery resistance from 64 to 16
        bit and accept packets that real FeliCa hardware rejects.

        """
        felica = nfc.tag.tt3_sony.FelicaStandard
        code = 0x21
        payload = bytearray([0x11] * 8)

        genuine = payload + felica._calculate_command_mac_des(code, payload)
        assert felica._check_packet_mac_des(genuine, code) is True

        # rebuild the MAC chain over a pre-image with a nonzero tail
        forged_mac = bytearray([(2 + len(payload) + 8) & 0xFF, code]) + tail
        for i in range(0, len(payload), 8):
            forged_mac = des_ecb_encrypt(forged_mac, payload[i:i+8])
        forged = payload + forged_mac
        assert felica._check_packet_mac_des(forged, code) is False

    def test_packet_mac_rejects_wrong_response_code(self):
        felica = nfc.tag.tt3_sony.FelicaStandard
        payload = bytearray([0x11] * 8)
        genuine = payload + felica._calculate_command_mac_des(0x21, payload)
        assert felica._check_packet_mac_des(genuine, 0x23) is False

    #
    # key derivation
    #

    def test_generate_service_keys_des(self):
        system_key = HEX('0001020304050607')
        area_key = HEX('1011121314151617')
        service_key = HEX('2021222324252627')
        group_key, user_key = \
            nfc.tag.tt3_sony.FelicaStandard.generate_service_keys_des(
                system_key, [area_key], [service_key])
        assert group_key == des_ecb_encrypt(system_key, area_key)
        assert user_key == des_ecb_encrypt(group_key, service_key)

    def test_generate_group_key_v2_aes128(self):
        node_keys = [bytearray(range(16)), bytearray(range(16, 32))]
        expected = bytearray(
            nfc.tag.tt3_sony.FelicaStandard.V2_AES128_NODE_KEY_INIT)
        for key in node_keys:
            expected = aes_ecb_encrypt(expected, key)
        assert nfc.tag.tt3_sony.FelicaStandard.generate_group_key_v2_aes128(
            node_keys) == expected

    #
    # secure session state
    #

    def test_no_session_after_activation(self, tag):
        assert tag.authenticated_context() is None
        assert tag.authenticated_scheme() is None

    def test_secure_command_requires_authentication(self, tag):
        with pytest.raises(RuntimeError) as excinfo:
            tag.read([nfc.tag.tt3.BlockCode(0)])
        assert str(excinfo.value) == "authentication required"
        assert tag.clf.exchange.mock_calls == []

    def test_set_and_clear_authenticated_context(self, tag):
        context = nfc.tag.tt3_sony.AuthenticatedContext(
            transaction_number=3,
            transaction_id=HEX('020304050607'),
            credentials=nfc.tag.tt3_sony.DesSecureSessionCredentials(
                HEX('a0a1a2a3a4a5a6a7')))
        tag.set_authenticated_context(context)
        assert tag.authenticated_scheme() == "des"

        # the context is copied in and out, not shared by reference
        stored = tag.authenticated_context()
        assert stored is not context
        assert stored.transaction_number == 3
        assert stored.transaction_id == HEX('020304050607')
        stored.transaction_number = 99
        assert tag.authenticated_context().transaction_number == 3

        tag.clear_authenticated_context()
        assert tag.authenticated_context() is None
        assert tag.authenticated_scheme() is None

    def test_set_authenticated_context_wrong_type(self, tag):
        with pytest.raises(TypeError) as excinfo:
            tag.set_authenticated_context(object())
        assert str(excinfo.value) == "context must be AuthenticatedContext"

    @pytest.mark.parametrize("transaction_id, message", [
        (HEX('0203040506'), "transaction_id must be 6 bytes"),
        (HEX('02030405060708'), "transaction_id must be 6 bytes"),
    ])
    def test_authenticated_context_bad_transaction_id(
            self, transaction_id, message):
        with pytest.raises(ValueError) as excinfo:
            nfc.tag.tt3_sony.AuthenticatedContext(
                transaction_number=0, transaction_id=transaction_id,
                credentials=nfc.tag.tt3_sony.DesSecureSessionCredentials(
                    HEX('a0a1a2a3a4a5a6a7')))
        assert str(excinfo.value) == message

    def test_authenticated_context_transaction_number_overflow(self):
        context = nfc.tag.tt3_sony.AuthenticatedContext(
            transaction_number=0xFFFF,
            transaction_id=HEX('020304050607'),
            credentials=nfc.tag.tt3_sony.DesSecureSessionCredentials(
                HEX('a0a1a2a3a4a5a6a7')))
        with pytest.raises(ValueError) as excinfo:
            context.increment_transaction_number()
        assert str(excinfo.value) == \
            "secure session transaction number overflow"

    def test_session_repr_never_contains_key_material(self):
        # One debug log of a session object would otherwise write the live
        # session key into an application log file.
        des = nfc.tag.tt3_sony.DesSecureSessionCredentials(
            HEX('deadbeefdeadbeef'))
        assert repr(des) == \
            "DesSecureSessionCredentials(session_key=<8 bytes redacted>)"

        aes = nfc.tag.tt3_sony.Aes128SecureSessionCredentials(
            encryption_key=bytearray(16 * [0xA1]),
            mac_key=bytearray(16 * [0xB2]),
            challenge_3c=HEX('01020304'))
        text = repr(aes)
        assert text.count("<16 bytes redacted>") == 2
        assert "a1a1" not in text and "b2b2" not in text
        # challenge_3c travels in the clear, so it stays visible
        assert "challenge_3c=01020304" in text

        context = nfc.tag.tt3_sony.AuthenticatedContext(
            transaction_number=7, transaction_id=HEX('020304050607'),
            credentials=des, nodes=[0x0009])
        text = repr(context)
        assert "transaction_number=7" in text
        assert "<8 bytes redacted>" in text
        assert "deadbeef" not in text

    def test_clear_authenticated_context_zeroizes_the_session_key(self, tag):
        credentials = nfc.tag.tt3_sony.DesSecureSessionCredentials(
            HEX('a0a1a2a3a4a5a6a7'))
        tag.set_authenticated_context(nfc.tag.tt3_sony.AuthenticatedContext(
            transaction_number=3, transaction_id=HEX('020304050607'),
            credentials=credentials))
        # the context is normalized into the tag, so reach for that copy
        stored = tag._authenticated_context
        assert stored.credentials.session_key == HEX('a0a1a2a3a4a5a6a7')
        tag.clear_authenticated_context()
        assert stored.credentials.session_key == bytearray(8)
        assert tag.authenticated_context() is None

    @pytest.mark.parametrize("status_flag1, expected", [
        (0x00, "normal completion"),
        (0xFF, "error not associated with a specific list entry"),
        # the 10th list entry is 0x0A in the ordinal encoding and 0x02 in
        # the bit encoding, which cannot tell entry 2 from entry 10
        (0x0A, "error at list position 10 (ordinal encoding) or 2/4/10/12 "
               "(bit encoding)"),
        (0x02, "error at list position 2 (ordinal encoding) or 2/10 "
               "(bit encoding)"),
        (0x80, "error at list position 128 (ordinal encoding) or 8 "
               "(bit encoding)"),
    ])
    def test_status_flag1_description(self, status_flag1, expected):
        assert nfc.tag.tt3_sony.status_flag1_description(status_flag1) \
            == expected

    #
    # DES mutual authentication and secure messaging
    #

    GSK = HEX('1112131415161718')   # group service key
    USK = HEX('2122232425262728')   # user service key
    RANDOM_2 = HEX('a0a1a2a3a4a5a6a7')
    ISSUE_ID = HEX('b0b1b2b3b4b5b6b7')
    ISSUE_PARAM = HEX('c0c1c2c3c4c5c6c7')

    def des_authenticate(self, tag, transaction_number=1):
        """Run a full DES mutual authentication against a simulated card."""
        random_1 = bytearray(range(8))  # os.urandom is mocked in the fixture
        key_l, alpha, beta = des_session_keys(STD_IDM, self.GSK, self.USK)
        challenge_1a = des3_encrypt(random_1, alpha, key_l)
        challenge_1b = des3_encrypt(random_1, key_l, beta)
        challenge_2a = des3_encrypt(self.RANDOM_2, key_l, beta)
        challenge_2b = des3_encrypt(self.RANDOM_2, alpha, key_l)
        transaction_id = random_1[2:8]
        payload = bytearray(struct.pack("<H", transaction_number)) \
            + transaction_id + self.ISSUE_ID + self.ISSUE_PARAM
        encrypted = des_cbc_encrypt(
            payload + des_packet_mac(0x13, payload), self.RANDOM_2)

        tag.clf.exchange.side_effect = [
            HEX('1a 11') + STD_IDM + challenge_1b + challenge_2a,
            HEX('22 13') + encrypted,
        ]
        result = tag.mutual_authentication(
            [0x0000], [nfc.tag.tt3.ServiceCode(0, 9)], self.GSK, self.USK)
        expected_calls = [
            mock.call(HEX('18 10') + STD_IDM
                      + HEX('01 0000 01 0900') + challenge_1a, STD_TIMEOUT_2),
            mock.call(HEX('12 12') + STD_IDM + challenge_2b, STD_TIMEOUT),
        ]
        return result, expected_calls, transaction_id

    def test_mutual_authentication(self, tag):
        result, expected_calls, transaction_id = self.des_authenticate(tag)
        assert result == (self.ISSUE_ID, self.ISSUE_PARAM)
        assert tag.clf.exchange.mock_calls == expected_calls

        context = tag.authenticated_context()
        assert tag.authenticated_scheme() == "des"
        assert context.transaction_number == 1
        assert context.transaction_id == transaction_id
        assert context.credentials.session_key == self.RANDOM_2

    def test_mutual_authentication_wrong_key(self, tag):
        # the card answers challenge_1b computed from a different key, so
        # the tag must refuse to continue after Authentication1
        tag.clf.exchange.side_effect = [
            HEX('1a 11') + STD_IDM + bytearray(16),
        ]
        with pytest.raises(RuntimeError) as excinfo:
            tag.mutual_authentication(
                [0x0000], [nfc.tag.tt3.ServiceCode(0, 9)], self.GSK, self.USK)
        assert str(excinfo.value) == "Authentication1 verification failed"
        assert tag.authenticated_context() is None

    def test_mutual_authentication_bad_mac(self, tag):
        random_1 = bytearray(range(8))
        key_l, alpha, beta = des_session_keys(STD_IDM, self.GSK, self.USK)
        challenge_1b = des3_encrypt(random_1, key_l, beta)
        challenge_2a = des3_encrypt(self.RANDOM_2, key_l, beta)
        payload = bytearray(struct.pack("<H", 1)) + random_1[2:8] \
            + self.ISSUE_ID + self.ISSUE_PARAM
        # append a wrong MAC
        encrypted = des_cbc_encrypt(payload + bytearray(8), self.RANDOM_2)
        tag.clf.exchange.side_effect = [
            HEX('1a 11') + STD_IDM + challenge_1b + challenge_2a,
            HEX('22 13') + encrypted,
        ]
        with pytest.raises(nfc.tag.tt3.Type3TagCommandError) as excinfo:
            tag.mutual_authentication(
                [0x0000], [nfc.tag.tt3.ServiceCode(0, 9)], self.GSK, self.USK)
        assert excinfo.value.errno == nfc.tag.PROTOCOL_ERROR
        assert tag.authenticated_context() is None

    @pytest.mark.parametrize("areas, services, message", [
        ([], [], "mutual authentication requires at least one area or "
                 "service"),
    ])
    def test_mutual_authentication_no_node(self, tag, areas, services,
                                           message):
        with pytest.raises(ValueError) as excinfo:
            tag.mutual_authentication(areas, services, self.GSK, self.USK)
        assert str(excinfo.value) == message

    def test_mutual_authentication_wrong_key_size(self, tag):
        with pytest.raises(ValueError) as excinfo:
            tag.mutual_authentication(
                [0x0000], [], self.GSK, HEX('21222324252627'))
        assert str(excinfo.value) == "service keys must be 8 bytes"

    def test_authentication1_wrong_challenge_size(self, tag):
        with pytest.raises(ValueError) as excinfo:
            tag.authentication1([0x0000], [], HEX('00010203040506'))
        assert str(excinfo.value) == "challenge_1a must be 8 bytes"

    def test_authentication2_wrong_challenge_size(self, tag):
        with pytest.raises(ValueError) as excinfo:
            tag.authentication2(HEX('00010203040506'))
        assert str(excinfo.value) == "challenge_2b must be 8 bytes"

    def test_secure_read(self, tag):
        self.des_authenticate(tag)
        reset_exchange(tag)

        block_data = bytearray(range(16))
        block_list = [nfc.tag.tt3.BlockCode(0)]
        # the command carries transaction number 2, the response 3
        command = des_secure_packet(
            0x14, 2, HEX('020304050607'), HEX('01 8000'), self.RANDOM_2)
        response = des_secure_packet(
            0x15, 3, HEX('020304050607'),
            HEX('0000 01') + block_data, self.RANDOM_2)

        tag.clf.exchange.return_value = \
            bytearray([len(response) + 2, 0x15]) + response
        assert tag.read(block_list) == [block_data]
        tag.clf.exchange.assert_called_once_with(
            bytearray([len(command) + 2, 0x14]) + command, STD_TIMEOUT_1)
        # the response transaction number is adopted for the next command
        assert tag.authenticated_context().transaction_number == 3

    def test_secure_read_stale_transaction_number(self, tag):
        self.des_authenticate(tag)
        reset_exchange(tag)

        # the card replays the command transaction number instead of
        # advancing it, which must be rejected
        response = des_secure_packet(
            0x15, 2, HEX('020304050607'),
            HEX('0000 01') + bytearray(16), self.RANDOM_2)
        tag.clf.exchange.return_value = \
            bytearray([len(response) + 2, 0x15]) + response
        with pytest.raises(nfc.tag.tt3.Type3TagCommandError) as excinfo:
            tag.read([nfc.tag.tt3.BlockCode(0)])
        assert excinfo.value.errno == nfc.tag.PROTOCOL_ERROR

    def test_secure_read_wrong_transaction_id(self, tag):
        self.des_authenticate(tag)
        reset_exchange(tag)

        response = des_secure_packet(
            0x15, 3, HEX('ffffffffffff'),
            HEX('0000 01') + bytearray(16), self.RANDOM_2)
        tag.clf.exchange.return_value = \
            bytearray([len(response) + 2, 0x15]) + response
        with pytest.raises(nfc.tag.tt3.Type3TagCommandError) as excinfo:
            tag.read([nfc.tag.tt3.BlockCode(0)])
        assert excinfo.value.errno == nfc.tag.PROTOCOL_ERROR

    def test_secure_read_block_count_mismatch(self, tag):
        self.des_authenticate(tag)
        reset_exchange(tag)

        response = des_secure_packet(
            0x15, 3, HEX('020304050607'),
            HEX('0000 02') + bytearray(32), self.RANDOM_2)
        tag.clf.exchange.return_value = \
            bytearray([len(response) + 2, 0x15]) + response
        with pytest.raises(nfc.tag.tt3.Type3TagCommandError) as excinfo:
            tag.read([nfc.tag.tt3.BlockCode(0)])
        assert excinfo.value.errno == nfc.tag.tt3.DATA_SIZE_ERROR

    def test_secure_write_wrong_data_size(self, tag):
        self.des_authenticate(tag)
        with pytest.raises(ValueError) as excinfo:
            tag.write([nfc.tag.tt3.BlockCode(0)], bytearray(15))
        assert str(excinfo.value) == "data length must be 16 * len(block_list)"

    def test_secure_write(self, tag):
        # A DES secure response is CBC encrypted and therefore padded to a
        # multiple of 8 byte, so the decrypted status flags arrive with
        # trailing padding and only a minimum length can be required.
        self.des_authenticate(tag)
        reset_exchange(tag)

        block_data = bytearray(range(16))
        command = des_secure_packet(
            0x16, 2, HEX('020304050607'),
            HEX('01 8000') + block_data, self.RANDOM_2)
        response = des_secure_packet(
            0x17, 3, HEX('020304050607'), HEX('0000'), self.RANDOM_2)

        tag.clf.exchange.return_value = \
            bytearray([len(response) + 2, 0x17]) + response
        assert tag.write([nfc.tag.tt3.BlockCode(0)], block_data) is None
        tag.clf.exchange.assert_called_once_with(
            bytearray([len(command) + 2, 0x16]) + command, STD_TIMEOUT_1)

    def test_secure_write_memory_rewrite_count_warning(self, tag):
        # Status flag 2 = 0x71 (memory rewrite count exceeded) is a warning
        # raised after the write has been performed, and some products pair
        # it with status flag 1 = 0x00. Such a response reports a completed
        # write and must not surface as an error, because the caller would
        # otherwise retry a write that already happened.
        self.des_authenticate(tag)
        reset_exchange(tag)

        block_data = bytearray(range(16))
        response = des_secure_packet(
            0x17, 3, HEX('020304050607'), HEX('0071'), self.RANDOM_2)
        tag.clf.exchange.return_value = \
            bytearray([len(response) + 2, 0x17]) + response
        assert tag.write([nfc.tag.tt3.BlockCode(0)], block_data) is None

    def test_mutual_authentication_records_the_service_list(self, tag):
        # The session records the services it was opened against, because a
        # block list element names its target by position in that list. The
        # area list only scopes the key chain and is not addressable.
        self.des_authenticate(tag)
        assert tag.authenticated_context().nodes == [0x0009]

    #
    # AES-128 (v2) mutual authentication and secure messaging
    #

    GROUP_KEY = HEX('101112131415161718191a1b1c1d1e1f')
    INDIVIDUAL_KEY = HEX('202122232425262728292a2b2c2d2e2f')
    RANDOM_2_V2 = HEX('a0a1a2a3a4a5a6a7a8a9aaabacadaeaf')
    CHALLENGE_3C = HEX('d0d1d2d3')

    def aes_authenticate(self, tag, transaction_number=1):
        """Run a full AES-128 mutual authentication against a card."""
        random_1 = bytearray(range(16))  # os.urandom is mocked
        h = xorbytes(self.GROUP_KEY, self.INDIVIDUAL_KEY)
        alpha = aes_ecb_encrypt(
            aes_v2_context_block([0x01, 0x02], STD_IDM), h)
        beta = aes_ecb_encrypt(
            aes_v2_context_block([0x02, 0x02], STD_IDM), h)
        beta_mask = bytearray(16)
        beta_mask[0:4] = self.CHALLENGE_3C
        beta_with_3c = xorbytes(beta, beta_mask)

        challenge_1a = aes_ecb_encrypt(random_1, alpha)
        challenge_1b = aes_ecb_encrypt(random_1, beta_with_3c)
        challenge_2a = aes_ecb_encrypt(self.RANDOM_2_V2, beta_with_3c)
        challenge_2b = aes_ecb_encrypt(self.RANDOM_2_V2, alpha)

        transaction_id = random_1[2:8]
        encryption_key = aes_ecb_encrypt(
            nfc.tag.tt3_sony.FelicaStandard
            .V2_AES128_DERIVE_ENCRYPTION_KEY_INPUT, self.RANDOM_2_V2)
        mac_key = aes_ecb_encrypt(
            nfc.tag.tt3_sony.FelicaStandard
            .V2_AES128_DERIVE_MAC_KEY_INPUT, self.RANDOM_2_V2)
        encrypted = aes_v2_secure_packet(
            0x43, transaction_number, transaction_id, self.CHALLENGE_3C,
            encryption_key, mac_key, self.ISSUE_ID + self.ISSUE_PARAM)

        tag.clf.exchange.side_effect = [
            HEX('2e 41') + STD_IDM + challenge_1b + challenge_2a
            + self.CHALLENGE_3C,
            bytearray([len(encrypted) + 2, 0x43]) + encrypted,
        ]
        result = tag.mutual_authentication_v2(
            0x00, [0x1008], self.GROUP_KEY, self.INDIVIDUAL_KEY)
        expected_calls = [
            mock.call(HEX('1e 40') + STD_IDM + HEX('00 01 0810')
                      + challenge_1a, STD_TIMEOUT_1),
            mock.call(HEX('1a 42') + STD_IDM + challenge_2b, STD_TIMEOUT),
        ]
        return (result, expected_calls, transaction_id,
                encryption_key, mac_key)

    def test_mutual_authentication_v2(self, tag):
        (result, expected_calls, transaction_id,
         encryption_key, mac_key) = self.aes_authenticate(tag)
        assert result == (self.ISSUE_ID, self.ISSUE_PARAM)
        assert tag.clf.exchange.mock_calls == expected_calls

        context = tag.authenticated_context()
        assert tag.authenticated_scheme() == "aes128"
        assert context.transaction_number == 1
        assert context.transaction_id == transaction_id
        assert context.credentials.encryption_key == encryption_key
        assert context.credentials.mac_key == mac_key
        assert context.credentials.challenge_3c == self.CHALLENGE_3C
        # a v2 session records the node list it was opened against
        assert context.nodes == [0x1008]

    def test_mutual_authentication_v2_wrong_key(self, tag):
        tag.clf.exchange.side_effect = [
            HEX('2e 41') + STD_IDM + bytearray(32) + self.CHALLENGE_3C,
        ]
        with pytest.raises(RuntimeError) as excinfo:
            tag.mutual_authentication_v2(
                0x00, [0x1008], self.GROUP_KEY, self.INDIVIDUAL_KEY)
        assert str(excinfo.value) == "Authentication1 v2 verification failed"
        assert tag.authenticated_context() is None

    def test_mutual_authentication_v2_no_node(self, tag):
        with pytest.raises(ValueError) as excinfo:
            tag.mutual_authentication_v2(
                0x00, [], self.GROUP_KEY, self.INDIVIDUAL_KEY)
        assert str(excinfo.value) == \
            "mutual authentication v2 requires at least one node code"

    def test_mutual_authentication_v2_wrong_key_size(self, tag):
        with pytest.raises(ValueError) as excinfo:
            tag.mutual_authentication_v2(
                0x00, [0x1008], self.GROUP_KEY, HEX('2021'))
        assert str(excinfo.value) == \
            "group_key and individual_key must be 16 bytes"

    def test_secure_read_v2(self, tag):
        _, _, transaction_id, encryption_key, mac_key = \
            self.aes_authenticate(tag)
        reset_exchange(tag)

        block_data = bytearray(range(16))
        command = aes_v2_secure_packet(
            0x44, 2, transaction_id, self.CHALLENGE_3C,
            encryption_key, mac_key, HEX('01 8000'))
        response = aes_v2_secure_packet(
            0x45, 3, transaction_id, self.CHALLENGE_3C,
            encryption_key, mac_key, HEX('0000 01') + block_data)

        tag.clf.exchange.return_value = \
            bytearray([len(response) + 2, 0x45]) + response
        assert tag.read_v2([nfc.tag.tt3.BlockCode(0)]) == [block_data]
        tag.clf.exchange.assert_called_once_with(
            bytearray([len(command) + 2, 0x44]) + command, STD_TIMEOUT_1)
        assert tag.authenticated_context().transaction_number == 3

    def test_secure_write_v2(self, tag):
        _, _, transaction_id, encryption_key, mac_key = \
            self.aes_authenticate(tag)
        reset_exchange(tag)

        block_data = bytearray(range(16))
        command = aes_v2_secure_packet(
            0x46, 2, transaction_id, self.CHALLENGE_3C,
            encryption_key, mac_key, HEX('01 8000') + block_data)
        response = aes_v2_secure_packet(
            0x47, 3, transaction_id, self.CHALLENGE_3C,
            encryption_key, mac_key, HEX('0000'))

        tag.clf.exchange.return_value = \
            bytearray([len(response) + 2, 0x47]) + response
        assert tag.write_v2([nfc.tag.tt3.BlockCode(0)], block_data) is None
        tag.clf.exchange.assert_called_once_with(
            bytearray([len(command) + 2, 0x46]) + command, STD_TIMEOUT_1)

    def test_secure_write_v2_status_error(self, tag):
        _, _, transaction_id, encryption_key, mac_key = \
            self.aes_authenticate(tag)
        reset_exchange(tag)

        response = aes_v2_secure_packet(
            0x47, 3, transaction_id, self.CHALLENGE_3C,
            encryption_key, mac_key, HEX('ffa2'))
        tag.clf.exchange.return_value = \
            bytearray([len(response) + 2, 0x47]) + response
        with pytest.raises(nfc.tag.tt3.Type3TagCommandError) as excinfo:
            tag.write_v2([nfc.tag.tt3.BlockCode(0)], bytearray(16))
        assert excinfo.value.errno == 0xFFA2

    def test_secure_read_v2_tampered_mac(self, tag):
        _, _, transaction_id, encryption_key, mac_key = \
            self.aes_authenticate(tag)
        reset_exchange(tag)

        response = aes_v2_secure_packet(
            0x45, 3, transaction_id, self.CHALLENGE_3C,
            encryption_key, mac_key, HEX('0000 01') + bytearray(16))
        response[-1] ^= 0xFF  # break the MAC
        tag.clf.exchange.return_value = \
            bytearray([len(response) + 2, 0x45]) + response
        with pytest.raises(nfc.tag.tt3.Type3TagCommandError) as excinfo:
            tag.read_v2([nfc.tag.tt3.BlockCode(0)])
        assert excinfo.value.errno == nfc.tag.PROTOCOL_ERROR

    #
    # issuance
    #

    PACKAGE_KEY = HEX('3031323334353637')

    def registration_package(self, package_plain):
        mac_key = bytearray([x ^ 0xFF for x in bytearray(self.PACKAGE_KEY)])
        mac = des_cbc_encrypt(package_plain, mac_key)[-8:]
        return des_cbc_encrypt(
            bytearray(package_plain) + mac, self.PACKAGE_KEY)

    def test_register_issue_id(self, tag):
        self.des_authenticate(tag)
        reset_exchange(tag)

        package_plain = bytearray(struct.pack(">H", 0x8092)) \
            + bytearray(struct.pack("<H", 1)) \
            + HEX('4041424344454647') + bytearray(4)
        package = self.registration_package(package_plain)
        command = des_secure_packet(
            0x80, 2, HEX('020304050607'),
            self.ISSUE_ID + self.ISSUE_PARAM + package, self.RANDOM_2)
        response = des_secure_packet(
            0x81, 3, HEX('020304050607'), HEX('0000 6400'), self.RANDOM_2)

        tag.clf.exchange.return_value = \
            bytearray([len(response) + 2, 0x81]) + response
        assert tag.register_issue_id(
            0x8092, 1, HEX('4041424344454647'), self.ISSUE_ID,
            self.ISSUE_PARAM, self.PACKAGE_KEY) == 100
        tag.clf.exchange.assert_called_once_with(
            bytearray([len(command) + 2, 0x80]) + command, STD_TIMEOUT)

    def test_register_area(self, tag):
        self.des_authenticate(tag)
        reset_exchange(tag)

        package_plain = bytearray(struct.pack("<HHHH", 0x1000, 0x1717, 4, 1)) \
            + HEX('4041424344454647')
        package = self.registration_package(package_plain)
        command = des_secure_packet(
            0x82, 2, HEX('020304050607'),
            HEX('0010') + package, self.RANDOM_2)
        response = des_secure_packet(
            0x83, 3, HEX('020304050607'), HEX('0000'), self.RANDOM_2)

        tag.clf.exchange.return_value = \
            bytearray([len(response) + 2, 0x83]) + response
        assert tag.register_area(
            0x1000, (0x1000, 0x1717), 4, 1, HEX('4041424344454647'),
            self.PACKAGE_KEY) is None
        tag.clf.exchange.assert_called_once_with(
            bytearray([len(command) + 2, 0x82]) + command, STD_TIMEOUT)

    def test_register_service(self, tag):
        self.des_authenticate(tag)
        reset_exchange(tag)

        package_plain = bytearray(struct.pack("<H", 0x1008)) + bytearray(2) \
            + bytearray(struct.pack("<H", 4)) \
            + bytearray(struct.pack("<H", 1)) + HEX('4041424344454647')
        package = self.registration_package(package_plain)
        command = des_secure_packet(
            0x84, 2, HEX('020304050607'),
            HEX('0810') + package, self.RANDOM_2)
        response = des_secure_packet(
            0x85, 3, HEX('020304050607'), HEX('0000 3200'), self.RANDOM_2)

        tag.clf.exchange.return_value = \
            bytearray([len(response) + 2, 0x85]) + response
        assert tag.register_service(
            0x1008, 4, 1, HEX('4041424344454647'), self.PACKAGE_KEY) == 50
        tag.clf.exchange.assert_called_once_with(
            bytearray([len(command) + 2, 0x84]) + command, STD_TIMEOUT)

    def test_register_service_wrong_key_size(self, tag):
        with pytest.raises(ValueError) as excinfo:
            tag.register_service(
                0x1008, 4, 1, HEX('40414243444546'), self.PACKAGE_KEY)
        assert str(excinfo.value) == "service_key must be 8 bytes"

    def test_register_area_wrong_key_size(self, tag):
        with pytest.raises(ValueError) as excinfo:
            tag.register_area(
                0x1000, (0x1000, 0x1717), 4, 1, HEX('40414243444546'),
                self.PACKAGE_KEY)
        assert str(excinfo.value) == "area_key must be 8 bytes"

    def test_change_system_block(self, tag):
        self.des_authenticate(tag)
        reset_exchange(tag)

        command = des_secure_packet(
            0x8E, 2, HEX('020304050607'), b'', self.RANDOM_2)
        response = des_secure_packet(
            0x8F, 3, HEX('020304050607'), HEX('0000'), self.RANDOM_2)

        tag.clf.exchange.return_value = \
            bytearray([len(response) + 2, 0x8F]) + response
        assert tag.change_system_block() is None
        tag.clf.exchange.assert_called_once_with(
            bytearray([len(command) + 2, 0x8E]) + command, STD_TIMEOUT)

    def test_change_system_block_rejected(self, tag):
        self.des_authenticate(tag)
        reset_exchange(tag)

        response = des_secure_packet(
            0x8F, 3, HEX('020304050607'), HEX('ffab'), self.RANDOM_2)
        tag.clf.exchange.return_value = \
            bytearray([len(response) + 2, 0x8F]) + response
        with pytest.raises(nfc.tag.tt3.Type3TagCommandError) as excinfo:
            tag.change_system_block()
        assert excinfo.value.errno == 0xFFAB

    def test_secure_transceive(self, tag):
        """Arbitrary commands can be driven through an open session."""
        self.des_authenticate(tag)
        reset_exchange(tag)

        command = des_secure_packet(
            0x3A, 2, HEX('020304050607'), HEX('0102'), self.RANDOM_2)
        response = des_secure_packet(
            0x3B, 3, HEX('020304050607'), HEX('00000304'), self.RANDOM_2)

        tag.clf.exchange.return_value = \
            bytearray([len(response) + 2, 0x3B]) + response
        payload = tag.secure_transceive(0x3A, HEX('0102'), STD_TIMEOUT)
        # the returned payload keeps the 8 byte alignment padding
        assert payload[0:4] == HEX('00000304')
        tag.clf.exchange.assert_called_once_with(
            bytearray([len(command) + 2, 0x3A]) + command, STD_TIMEOUT)

    def test_change_keys_write_command(self, tag):
        """The key change parameters are sent through the secure Write."""
        self.des_authenticate(tag)
        reset_exchange(tag)

        parent_key = HEX('4041424344454647')
        new_key = HEX('5051525354555657')
        old_key = HEX('6061626364656667')
        version_block = bytearray(8)
        version_block[6:8] = struct.pack("<H", 2)
        # both parameters are folded through the key hierarchy, the new key
        # version block through all three keys and the new key through two
        parameter1 = des_ecb_encrypt(
            des_ecb_encrypt(
                des_ecb_encrypt(version_block, new_key), old_key), parent_key)
        parameter2 = des_ecb_encrypt(
            des_ecb_encrypt(new_key, old_key), parent_key)
        command = des_secure_packet(
            0x16, 2, HEX('020304050607'),
            HEX('01') + nfc.tag.tt3.BlockCode(2, access=4, service=0).pack()
            + parameter1 + parameter2, self.RANDOM_2)
        response = des_secure_packet(
            0x17, 3, HEX('020304050607'), HEX('0000'), self.RANDOM_2)

        tag.clf.exchange.return_value = \
            bytearray([len(response) + 2, 0x17]) + response
        assert tag.change_keys([{
            "node": 0x0009,
            "parent_key": parent_key,
            "new_key": new_key,
            "old_key": old_key,
            "new_key_version": 2,
        }]) is None
        tag.clf.exchange.assert_called_once_with(
            bytearray([len(command) + 2, 0x16]) + command, STD_TIMEOUT_1)

    def test_change_keys_addresses_the_named_node(self, tag):
        """The block list element points at the node's list position."""
        self.des_authenticate(tag)
        reset_exchange(tag)
        # a session opened against two services, the second one is 0xFFFF
        context = tag.authenticated_context()
        context.nodes = [0x0009, 0xFFFF]
        tag.set_authenticated_context(context)

        parent_key = HEX('4041424344454647')
        new_key = HEX('5051525354555657')
        old_key = HEX('6061626364656667')
        version_block = bytearray(8)
        version_block[6:8] = struct.pack("<H", 3)
        parameter1 = des_ecb_encrypt(
            des_ecb_encrypt(
                des_ecb_encrypt(version_block, new_key), old_key), parent_key)
        parameter2 = des_ecb_encrypt(
            des_ecb_encrypt(new_key, old_key), parent_key)
        # the system node sits at position 1 of the node list
        command = des_secure_packet(
            0x16, 2, HEX('020304050607'),
            HEX('01') + nfc.tag.tt3.BlockCode(3, access=4, service=1).pack()
            + parameter1 + parameter2, self.RANDOM_2)
        response = des_secure_packet(
            0x17, 3, HEX('020304050607'), HEX('0000'), self.RANDOM_2)

        tag.clf.exchange.return_value = \
            bytearray([len(response) + 2, 0x17]) + response
        assert tag.change_keys([{
            "node": 0xFFFF,
            "parent_key": parent_key,
            "new_key": new_key,
            "old_key": old_key,
            "new_key_version": 3,
        }]) is None
        tag.clf.exchange.assert_called_once_with(
            bytearray([len(command) + 2, 0x16]) + command, STD_TIMEOUT_1)

    def test_change_keys_rejects_node_outside_session(self, tag):
        # A key change names its node by position in the list the session
        # was opened against, so a node that list does not contain has no
        # position to use. Sending it anyway would rewrite the key of
        # whichever node does sit at the position.
        self.des_authenticate(tag)
        reset_exchange(tag)
        with pytest.raises(ValueError) as excinfo:
            tag.change_keys([{
                "node": 0x1008,
                "parent_key": HEX('4041424344454647'),
                "new_key": HEX('5051525354555657'),
                "old_key": HEX('6061626364656667'),
                "new_key_version": 2,
            }])
        assert str(excinfo.value) == \
            "node 0x1008 is not in the authenticated node list ['0x0009']"
        assert tag.clf.exchange.mock_calls == []

    def test_change_keys_rejects_unaddressable_node_position(self, tag):
        # The service list index of a block list element is four bits wide.
        self.des_authenticate(tag)
        reset_exchange(tag)
        context = tag.authenticated_context()
        context.nodes = list(range(0x1000, 0x1011))
        tag.set_authenticated_context(context)
        with pytest.raises(ValueError) as excinfo:
            tag.change_keys([{
                "node": 0x1010,
                "parent_key": HEX('4041424344454647'),
                "new_key": HEX('5051525354555657'),
                "old_key": HEX('6061626364656667'),
                "new_key_version": 2,
            }])
        assert str(excinfo.value) == (
            "node 0x1010 is at position 16 of the authenticated node list, "
            "which a block list element cannot address")
        assert tag.clf.exchange.mock_calls == []

    def test_register_issue_id_wrong_key_size(self, tag):
        with pytest.raises(ValueError) as excinfo:
            tag.register_issue_id(
                0x8092, 1, HEX('40414243444546'), self.ISSUE_ID,
                self.ISSUE_PARAM, self.PACKAGE_KEY)
        assert str(excinfo.value) == \
            "area0_key, issue_id and issue_parameter must be 8 bytes"

    def test_register_area_code_mismatch(self, tag):
        with pytest.raises(ValueError) as excinfo:
            tag.register_area(
                0x1000, (0x1001, 0x1717), 4, 1, HEX('4041424344454647'),
                self.PACKAGE_KEY)
        assert str(excinfo.value) == \
            "area_code must match service_code_range start"

    def test_change_keys_requires_entries(self, tag):
        with pytest.raises(ValueError) as excinfo:
            tag.change_keys([])
        assert str(excinfo.value) == "change_keys requires at least one entry"

    def test_change_keys_wrong_key_size(self, tag):
        with pytest.raises(ValueError) as excinfo:
            tag.change_keys([{
                "node": 0x0009,
                "parent_key": HEX('4041424344454647'),
                "new_key": HEX('50515253545556'),
                "old_key": HEX('6061626364656667'),
                "new_key_version": 2,
            }])
        assert str(excinfo.value) == "all key values must be 8 bytes"


###############################################################################
#
# FeliCa Mobile
#
###############################################################################
class TestFelicaMobile:
    @pytest.mark.parametrize("ic_code, product", [
        ('06', "FeliCa Mobile 1.0"),
        ('07', "FeliCa Mobile 1.0"),
        ('10', "FeliCa Mobile 2.0"),
        ('11', "FeliCa Mobile 2.0"),
        ('12', "FeliCa Mobile 2.0"),
        ('13', "FeliCa Mobile 2.0"),
        ('14', "FeliCa Mobile 3.0"),
        ('15', "FeliCa Mobile 3.0"),
        ('16', "FeliCa Mobile 3.0"),
        ('17', "FeliCa Mobile 3.0"),
        ('18', "FeliCa Mobile 3.0"),
        ('19', "FeliCa Mobile 3.0"),
        ('1A', "FeliCa Mobile 3.0"),
        ('1B', "FeliCa Mobile 3.0"),
        ('1C', "FeliCa Mobile 3.0"),
        ('1D', "FeliCa Mobile 3.0"),
        ('1E', "FeliCa Mobile 3.0"),
        ('1F', "FeliCa Mobile 3.0"),
    ])
    def test_init(self, ic_code, product):
        sensf_res = HEX("01 0102030405060708 00%sFFFFFFFFFFFF 0000" % ic_code)
        target = nfc.clf.RemoteTarget("212F", sensf_res=sensf_res)
        tag = nfc.tag.activate(clf, target)
        assert isinstance(tag, nfc.tag.tt3_sony.FelicaMobile)
        assert tag.product == product


###############################################################################
#
# FeliCa Lite
#
###############################################################################
felica_lite_data_1 = [
    HEX("1d 07 0102030405060708 0000 01 10040100030000000000010000270040"),
    HEX('1d 07 0102030405060708 0000 01 d10222537091010e55036e66632d666f'),
    HEX("1d 07 0102030405060708 0000 01 72756d2e6f726751010c5402656e4e46"),
    HEX("1d 07 0102030405060708 0000 01 4320466f72756d000000000000000000"),
    HEX("1d 07 0102030405060708 0000 01 4320466f72756d000000000000000000"),
    HEX("1d 07 0102030405060708 0000 01 4320466f72756d000000000000000000"),
] + 18 * [
    HEX('1d 07 0102030405060708 0000 01') + bytearray(16)
]

felica_lite_dump_1 = [
    "  0: 10 04 01 00 03 00 00 00 00 00 01 00 00 27 00 40 |.............'.@|",
    '  1: d1 02 22 53 70 91 01 0e 55 03 6e 66 63 2d 66 6f |.."Sp...U.nfc-fo|',
    "  2: 72 75 6d 2e 6f 72 67 51 01 0c 54 02 65 6e 4e 46 |rum.orgQ..T.enNF|",
    "  3: 43 20 46 6f 72 75 6d 00 00 00 00 00 00 00 00 00 |C Forum.........|",
    "  *  43 20 46 6f 72 75 6d 00 00 00 00 00 00 00 00 00 |C Forum.........|",
    "  6: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|",
    "  *  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|",
    " 13: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|",
    " 14: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (REGA[4]B[4]C[8])",
    "128: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (RC1[8], RC2[8])",
    "129: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (MAC[8])",
    "130: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (IDD[8], DFC[2])",
    "131: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (IDM[8], PMM[8])",
    "132: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (SERVICE_CODE[2])",
    "133: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (SYSTEM_CODE[2])",
    "134: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (CKV[2])",
    "135: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (CK1[8], CK2[8])",
    "136: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (MEMORY_CONFIG)",
]

felica_lite_data_2 = [
    HEX("1d 07 0102030405060708 0000 01 10040100030000000000010000270040"),
    HEX('1d 07 0102030405060708 0000 01 d10222537091010e55036e66632d666f'),
    HEX("1d 07 0102030405060708 0000 01 72756d2e6f726751010c5402656e4e46"),
    HEX("1d 07 0102030405060708 0000 01 4320466f72756d000000000000000000"),
    HEX("0c 07 0102030405060708 FFFF"),
] + 18 * [
    HEX('1d 07 0102030405060708 0000 01') + bytearray(16)
] + [
    HEX("0c 07 0102030405060708 FFFF"),
]

felica_lite_dump_2 = [
    "  0: 10 04 01 00 03 00 00 00 00 00 01 00 00 27 00 40 |.............'.@|",
    '  1: d1 02 22 53 70 91 01 0e 55 03 6e 66 63 2d 66 6f |.."Sp...U.nfc-fo|',
    "  2: 72 75 6d 2e 6f 72 67 51 01 0c 54 02 65 6e 4e 46 |rum.orgQ..T.enNF|",
    "  3: 43 20 46 6f 72 75 6d 00 00 00 00 00 00 00 00 00 |C Forum.........|",
    "  4: ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? |................|",
    "  5: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|",
    "  *  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|",
    " 13: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|",
    " 14: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (REGA[4]B[4]C[8])",
    "128: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (RC1[8], RC2[8])",
    "129: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (MAC[8])",
    "130: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (IDD[8], DFC[2])",
    "131: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (IDM[8], PMM[8])",
    "132: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (SERVICE_CODE[2])",
    "133: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (SYSTEM_CODE[2])",
    "134: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (CKV[2])",
    "135: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (CK1[8], CK2[8])",
    "136: ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? (MEMORY_CONFIG)",
]


class TestFelicaLite:
    @pytest.fixture()
    def target(self):
        target = nfc.clf.RemoteTarget("212F")
        target.sensf_res = HEX("01 0102030405060708 00F0FFFFFFFFFFFF 88B4")
        return target

    @pytest.fixture()
    def tag(self, clf, target):
        tag = nfc.tag.activate(clf, target)
        assert isinstance(tag, nfc.tag.tt3_sony.FelicaLite)
        return tag

    @pytest.mark.parametrize("ic_code, product", [
        ('F0', "FeliCa Lite (RC-S965)"),
    ])
    def test_init(self, target, ic_code, product):
        target.sensf_res[10] = HEX(ic_code)[0]
        tag = nfc.tag.activate(clf, target)
        assert isinstance(tag, nfc.tag.tt3_sony.FelicaLite)
        assert tag.product == product

    @pytest.mark.parametrize("data, dump", [
        (felica_lite_data_1, felica_lite_dump_1),
        (felica_lite_data_2, felica_lite_dump_2),
    ])
    def test_dump(self, tag, data, dump):
        tag.clf.exchange.side_effect = data
        assert tag.dump() == dump

    def test_ndef(self, tag):
        tag.clf.exchange.side_effect = [
            # authenticate
            HEX('0c 09 0102030405060708 0000'),  # write block 0x80
            HEX('2d 07 0102030405060708 0000 01'  # read block 0x82, 0x81
                '00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00'
                'cc 97 f1 b9  7b 8b bc 79  00 00 00 00  00 00 00 00'),
            # ndef reading
            HEX("12 01 0102030405060708 FFFFFFFFFFFFFFFF"),
            HEX('2d 07 0102030405060708 0000 02'
                '10 04 01 00  03 00 00 00  00 00 01 00  00 27 00 40'
                'af 36 b1 f1  52 4e 3e b9  00 00 00 00  00 00 00 00'),
            HEX('4d 07 0102030405060708 0000 04'
                'd1 02 22 53  70 91 01 0e  55 03 6e 66  63 2d 66 6f'
                '72 75 6d 2e  6f 72 67 51  01 0c 54 02  65 6e 4e 46'
                '43 20 46 6f  72 75 6d 00  00 00 00 00  00 00 00 00'
                '9e 2d 7f e1  5b 2f 5d 1c  00 00 00 00  00 00 00 00'),
            # ndef writing
            HEX('2d 07 0102030405060708 0000 02'
                '10 04 01 00  03 00 00 00  00 00 01 00  00 27 00 40'
                'af 36 b1 f1  52 4e 3e b9  00 00 00 00  00 00 00 00'),
            HEX('0c 09 0102030405060708 0000'),  # write block 0
            HEX('0c 09 0102030405060708 0000'),  # write block 1
            HEX('0c 09 0102030405060708 0000'),  # write block 0
            nfc.clf.TimeoutError, nfc.clf.TimeoutError, nfc.clf.TimeoutError,
        ]
        assert tag.authenticate(b"0123456789abcdef") is True
        assert tag.ndef is not None
        assert tag.ndef._original_nbr == 4
        assert tag.ndef.capacity == 48
        assert tag.ndef.length == 39
        assert tag.ndef.is_readable is True
        assert tag.ndef.is_writeable is True
        tag.ndef.octets = HEX('d1 01 05 54 02 65 6e') + b'ab'
        assert tag.clf.exchange.mock_calls == [
            # authenticate
            mock.call(HEX('20 08 0102030405060708 010900 018080'
                          '07060504 03020100 0f0e0d0c 0b0a0908'), 0.3093504),
            mock.call(HEX('12 06 0102030405060708 010b00 0280828081'),
                      0.46402560000000004),
            # ndef read
            mock.call(HEX('06 00 12fc 0000'), 0.003625),
            mock.call(HEX('12 06 0102030405060708 010b00 0280008081'),
                      0.46402560000000004),
            mock.call(HEX('16 06 0102030405060708 010b00 048001800280038081'),
                      0.7733760000000001),
            # ndef write
            mock.call(HEX('12 06 0102030405060708 010b00 0280008081'),
                      0.46402560000000004),
            mock.call(HEX('20 08 0102030405060708 010900 018000'
                          '10040100 03000000 000f0100 0027004f'), 0.3093504),
            mock.call(HEX('20 08 0102030405060708 010900 018001'
                          'd1010554 02656e61 62000000 00000000'), 0.3093504),
            mock.call(HEX('20 08 0102030405060708 010900 018000'
                          '10040100 03000000 00000100 00090022'), 0.3093504),
        ]

    @pytest.mark.parametrize("flip_key, mac_result", [
        (False, "0b1268d7a4ac6932"),
        (True, "18cdd33c0fb25dd7"),
    ])
    def test_generate_mac(self, flip_key, mac_result):
        data = bytearray(range(32))
        key = bytearray(range(16))
        iv = bytearray(range(8))
        mac = nfc.tag.tt3_sony.FelicaLite.generate_mac(data, key, iv, flip_key)
        assert mac == HEX(mac_result)

    def test_read_with_mac(self, tag):
        with pytest.raises(RuntimeError) as excinfo:
            tag.read_with_mac(0, 1)
        assert str(excinfo.value) == "authentication required"

        tag.clf.exchange.side_effect = [
            HEX("3d 07 0102030405060708 0000 03") + bytearray(48),
        ]
        tag._sk = bytearray(range(16))
        tag._iv = bytearray(range(8))
        assert tag.read_with_mac(0, 1) is None
        tag.clf.exchange.assert_called_once_with(
            HEX('14 06 0102030405060708 01 0b00 03 8000 8001 8081'), 0.6187008)

    def test_protect(self, tag):
        with pytest.raises(ValueError) as excinfo:
            tag.protect("abc")
        assert str(excinfo.value) == "password must be at least 16 byte"

        with pytest.raises(ValueError) as excinfo:
            tag.protect("0123456789abcdef", protect_from=-1)
        assert str(excinfo.value) == "protect_from can not be negative"

        print("step: this tag can not be made read protected")
        assert tag.protect("0123456789abcdef", read_protect=True) is False

        print("step: system block protected, can't write key")
        tag.clf.exchange.side_effect = [
            HEX("1d 07 0102030405060708 0000 01"
                "FF FF 00 01  07 00 00 00  00 00 00 00  00 00 00 00"),
        ]
        assert tag.protect("0123456789abcdef") is False
        tag.clf.exchange.assert_called_with(
            HEX('10 06 0102030405060708 010b00 018088'), 0.3093504)

        print("step: also set ndef rw flag because tag has ndef")
        tag.clf.exchange.reset_mock()
        tag.clf.exchange.side_effect = [
            HEX('1d 07 0102030405060708 0000 01'
                'FF FF FF 01  07 00 00 00  00 00 00 00  00 00 00 00'),
            HEX('0c 09 0102030405060708 0000'),
            HEX("12 01 0102030405060708 00F0FFFFFFFFFFFF"),
            HEX('1d 07 0102030405060708 0000 01'
                '10 01 01 00  05 00 00 00  00 00 01 00  00 10 00 28'),
            HEX('1d 07 0102030405060708 0000 01'
                'd1 02 0b 53  70 d1 01 07  55 03 61 62  2e 63 6f 6d'),
            HEX('1d 07 0102030405060708 0000 01'
                '10 01 01 00  05 00 00 00  00 00 01 00  00 10 00 28'),
            HEX('0c 09 0102030405060708 0000'),
            HEX('0c 09 0102030405060708 0000'),
        ]
        assert tag.protect(b"0123456789abcdef") is True
        assert tag.clf.exchange.mock_calls == [
            mock.call(HEX('10 06 0102030405060708 010b00 018088'), 0.3093504),
            mock.call(HEX('20 08 0102030405060708 010900 018087'
                          '37363534 33323130 66656463 62613938'), 0.3093504),
            mock.call(HEX('060012fc0000'), 0.003625),
            mock.call(HEX('10 06 0102030405060708 010b00 018000'), 0.3093504),
            mock.call(HEX('10 06 0102030405060708 010b00 018001'), 0.3093504),
            mock.call(HEX('10 06 0102030405060708 010b00 018000'), 0.3093504),
            mock.call(HEX('20 08 0102030405060708 010900 018000'
                          '10010100 05000000 00000000 00100027'), 0.3093504),
            mock.call(HEX('20 08 0102030405060708 010900 018088'
                          '00400001 07000000 00000000 00000000'), 0.3093504),
        ]

        print("step: not setting ndef rw flag because protect_from > 0")
        tag.clf.exchange.reset_mock()
        tag.clf.exchange.side_effect = [
            HEX('1d 07 0102030405060708 0000 01'
                'FF FF FF 01  07 00 00 00  00 00 00 00  00 00 00 00'),
            HEX('0c 09 0102030405060708 0000'),
            HEX('0c 09 0102030405060708 0000'),
        ]
        assert tag.protect(b"0123456789abcdef", protect_from=1) is True
        assert tag.clf.exchange.mock_calls == [
            mock.call(HEX('10 06 0102030405060708 010b00 018088'), 0.3093504),
            mock.call(HEX('20 08 0102030405060708 010900 018087'
                          '37363534 33323130 66656463 62613938'), 0.3093504),
            mock.call(HEX('20 08 0102030405060708 010900 018088'
                          '01400001 07000000 00000000 00000000'), 0.3093504),
        ]

        print("step: not setting ndef rw flag because protect_from > 0")
        tag.clf.exchange.reset_mock()
        tag.clf.exchange.side_effect = [
            HEX('1d 07 0102030405060708 0000 01'
                'FF FF FF 01  07 00 00 00  00 00 00 00  00 00 00 00'),
            HEX('0c 09 0102030405060708 0000'),
        ]
        assert tag.protect(None, protect_from=14) is True
        print(tag.clf.exchange.mock_calls)
        assert tag.clf.exchange.mock_calls == [
            mock.call(HEX('10 06 0102030405060708 010b00 018088'), 0.3093504),
            mock.call(HEX('20 08 0102030405060708 010900 018088'
                          'ffff0001 07000000 00000000 00000000'), 0.3093504),
        ]

    def test_authenticate(self, tag):
        # test invalid password (too short)
        with pytest.raises(ValueError) as excinfo:
            tag.authenticate(b"abc")
        assert str(excinfo.value) == "password must be at least 16 byte"

        # test successful authentication
        tag.clf.exchange.side_effect = [
            HEX('0c 09 0102030405060708 0000'),
            HEX('2d 07 0102030405060708 0000 01'  # block number 82, 81
                '00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00'
                'cc 97 f1 b9  7b 8b bc 79  00 00 00 00  00 00 00 00'),
        ]
        assert tag.authenticate(b"0123456789abcdef") is True
        assert tag.clf.exchange.mock_calls == [
            mock.call(HEX('20 08 0102030405060708 010900 018080'
                          '07060504 03020100 0f0e0d0c 0b0a0908'), 0.3093504),
            mock.call(HEX('12 06 0102030405060708 010b00 0280828081'),
                      0.46402560000000004),
        ]

        # test failed authentication (wrong mac)
        tag.clf.exchange.reset_mock()
        tag.clf.exchange.side_effect = [
            HEX('0c 09 0102030405060708 0000'),
            HEX('2d 07 0102030405060708 0000 01'  # block number 82, 81
                '00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00'
                '00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00'),
        ]
        assert tag.authenticate(b"0123456789abcdef") is False
        assert tag.clf.exchange.mock_calls == [
            mock.call(HEX('20 08 0102030405060708 010900 018080'
                          '07060504 03020100 0f0e0d0c 0b0a0908'), 0.3093504),
            mock.call(HEX('12 06 0102030405060708 010b00 0280828081'),
                      0.46402560000000004),
        ]

    def test_format(self, tag):
        with pytest.raises(AssertionError):
            tag.format(version='')

        with pytest.raises(AssertionError):
            tag.format(wipe='')

        # test invalid ndef mapping major version
        assert tag.format(version=0xF0) is False

        # the first user data block is not writeable
        tag.clf.exchange.reset_mock()
        tag.clf.exchange.side_effect = [
            HEX('1d 07 0102030405060708 0000 01'  # block number 88
                'FE FF FF 01  07 00 00 00  00 00 00 00  00 00 00 00'),
        ]
        assert tag.format() is False
        assert tag.clf.exchange.mock_calls == [
            mock.call(HEX('10 06 0102030405060708 010b00 018088'), 0.3093504),
        ]

        # ndef system code not enabled and MC block is read-only
        tag.clf.exchange.reset_mock()
        tag.clf.exchange.side_effect = [
            HEX('1d 07 0102030405060708 0000 01'  # block number 88
                'FF FF 00 00  07 00 00 00  00 00 00 00  00 00 00 00'),
        ]
        assert tag.format() is False
        assert tag.clf.exchange.mock_calls == [
            mock.call(HEX('10 06 0102030405060708 010b00 018088'), 0.3093504),
        ]

        # enable ndef system code, all data blocks writable, version 1.15
        tag.clf.exchange.reset_mock()
        tag.clf.exchange.side_effect = [
            HEX('1d 07 0102030405060708 0000 01'  # read block 88
                'FF FF FF 00  07 00 00 00  00 00 00 00  00 00 00 00'),
            HEX('0c 09 0102030405060708 0000'),  # write block 88
            HEX('0c 09 0102030405060708 0000'),  # write block 0
        ]
        assert tag.format(version=0x1F) is True
        assert tag.clf.exchange.mock_calls == [
            mock.call(HEX('10 06 0102030405060708 010b00 018088'), 0.3093504),
            mock.call(HEX('20 08 0102030405060708 010900 018088'
                          'FFFFFF01 07000000 00000000 00000000'), 0.3093504),
            mock.call(HEX('20 08 0102030405060708 010900 018000'
                          '1F040100 0d000000 00000100 00000032'), 0.3093504),
        ]

        # last user data block is read-only
        tag.clf.exchange.reset_mock()
        tag.clf.exchange.side_effect = [
            HEX('1d 07 0102030405060708 0000 01'  # read block 88
                'FF DF FF 01  07 00 00 00  00 00 00 00  00 00 00 00'),
            HEX('0c 09 0102030405060708 0000'),  # write block 0
        ]
        assert tag.format() is True
        assert tag.clf.exchange.mock_calls == [
            mock.call(HEX('10 06 0102030405060708 010b00 018088'), 0.3093504),
            mock.call(HEX('20 08 0102030405060708 010900 018000'
                          '10040100 0c000000 00000100 00000022'), 0.3093504),
        ]

        # only first ndef data block is writable, wipe with 0xA5
        tag.clf.exchange.reset_mock()
        tag.clf.exchange.side_effect = [
            HEX('1d 07 0102030405060708 0000 01'  # read block 88
                '03 C0 FF 01  07 00 00 00  00 00 00 00  00 00 00 00'),
            HEX('0c 09 0102030405060708 0000'),  # write block 0
            HEX('0c 09 0102030405060708 0000'),  # write block 1

            HEX('0c 09 0102030405060708 0000'),  # write block 1
            HEX('0c 09 0102030405060708 0000'),  # write block 1
            HEX('0c 09 0102030405060708 0000'),  # write block 1
            HEX('0c 09 0102030405060708 0000'),  # write block 1
            HEX('0c 09 0102030405060708 0000'),  # write block 1
            HEX('0c 09 0102030405060708 0000'),  # write block 1
        ]
        assert tag.format(wipe=0xA5) is True
        print(tag.clf.exchange.mock_calls)
        assert tag.clf.exchange.mock_calls == [
            mock.call(HEX('10 06 0102030405060708 010b00 018088'), 0.3093504),
            mock.call(HEX('20 08 0102030405060708 010900 018000'
                          '10040100 01000000 00000100 00000017'), 0.3093504),
            mock.call(HEX('20 08 0102030405060708 010900 018001'
                          'a5a5a5a5 a5a5a5a5 a5a5a5a5 a5a5a5a5'), 0.3093504),
        ]


###############################################################################
#
# FeliCa Lite-S
#
###############################################################################
felica_lites_data_1 = [
    HEX("1d 07 0102030405060708 0000 01 10040100030000000000010000270040"),
    HEX('1d 07 0102030405060708 0000 01 d10222537091010e55036e66632d666f'),
    HEX("1d 07 0102030405060708 0000 01 72756d2e6f726751010c5402656e4e46"),
    HEX("1d 07 0102030405060708 0000 01 4320466f72756d000000000000000000"),
    HEX("1d 07 0102030405060708 0000 01 4320466f72756d000000000000000000"),
    HEX("1d 07 0102030405060708 0000 01 4320466f72756d000000000000000000"),
] + 21 * [
    HEX('1d 07 0102030405060708 0000 01') + bytearray(16)
]

felica_lites_dump_1 = [
    "  0: 10 04 01 00 03 00 00 00 00 00 01 00 00 27 00 40 |.............'.@|",
    '  1: d1 02 22 53 70 91 01 0e 55 03 6e 66 63 2d 66 6f |.."Sp...U.nfc-fo|',
    "  2: 72 75 6d 2e 6f 72 67 51 01 0c 54 02 65 6e 4e 46 |rum.orgQ..T.enNF|",
    "  3: 43 20 46 6f 72 75 6d 00 00 00 00 00 00 00 00 00 |C Forum.........|",
    "  *  43 20 46 6f 72 75 6d 00 00 00 00 00 00 00 00 00 |C Forum.........|",
    "  6: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|",
    "  *  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|",
    " 13: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|",
    " 14: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (REGA[4]B[4]C[8])",
    "128: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (RC1[8], RC2[8])",
    "129: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (MAC[8])",
    "130: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (IDD[8], DFC[2])",
    "131: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (IDM[8], PMM[8])",
    "132: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (SERVICE_CODE[2])",
    "133: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (SYSTEM_CODE[2])",
    "134: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (CKV[2])",
    "135: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (CK1[8], CK2[8])",
    "136: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (MEMORY_CONFIG)",
    '144: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (WCNT[3])',
    '145: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (MAC_A[8])',
    '146: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (STATE)',
]

felica_lites_data_2 = [
    HEX("1d 07 0102030405060708 0000 01 10040100030000000000010000270040"),
    HEX('1d 07 0102030405060708 0000 01 d10222537091010e55036e66632d666f'),
    HEX("1d 07 0102030405060708 0000 01 72756d2e6f726751010c5402656e4e46"),
    HEX("1d 07 0102030405060708 0000 01 4320466f72756d000000000000000000"),
    HEX("0c 07 0102030405060708 FFFF"),
] + 21 * [
    HEX('1d 07 0102030405060708 0000 01') + bytearray(16)
] + [
    HEX("0c 07 0102030405060708 FFFF"),
]

felica_lites_dump_2 = [
    "  0: 10 04 01 00 03 00 00 00 00 00 01 00 00 27 00 40 |.............'.@|",
    '  1: d1 02 22 53 70 91 01 0e 55 03 6e 66 63 2d 66 6f |.."Sp...U.nfc-fo|',
    "  2: 72 75 6d 2e 6f 72 67 51 01 0c 54 02 65 6e 4e 46 |rum.orgQ..T.enNF|",
    "  3: 43 20 46 6f 72 75 6d 00 00 00 00 00 00 00 00 00 |C Forum.........|",
    "  4: ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? |................|",
    "  5: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|",
    "  *  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|",
    " 13: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|",
    " 14: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (REGA[4]B[4]C[8])",
    "128: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (RC1[8], RC2[8])",
    "129: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (MAC[8])",
    "130: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (IDD[8], DFC[2])",
    "131: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (IDM[8], PMM[8])",
    "132: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (SERVICE_CODE[2])",
    "133: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (SYSTEM_CODE[2])",
    "134: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (CKV[2])",
    "135: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (CK1[8], CK2[8])",
    "136: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (MEMORY_CONFIG)",
    '144: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (WCNT[3])',
    '145: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (MAC_A[8])',
    '146: ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? (STATE)',
]


class TestFelicaLiteS:
    @pytest.fixture()
    def target(self):
        target = nfc.clf.RemoteTarget("212F")
        target.sensf_res = HEX("01 0102030405060708 00F1FFFFFFFFFFFF 88B4")
        return target

    @pytest.fixture()
    def tag(self, clf, target):
        tag = nfc.tag.activate(clf, target)
        assert isinstance(tag, nfc.tag.tt3_sony.FelicaLiteS)
        return tag

    @pytest.mark.parametrize("ic_code, product", [
        ('F1', "FeliCa Lite-S (RC-S966)"),
        ('F2', "FeliCa Link (RC-S730) Lite-S Mode"),
    ])
    def test_init(self, target, ic_code, product):
        target.sensf_res[10] = HEX(ic_code)[0]
        tag = nfc.tag.activate(clf, target)
        assert isinstance(tag, nfc.tag.tt3_sony.FelicaLiteS)
        assert tag.product == product

    @pytest.mark.parametrize("data, dump", [
        (felica_lites_data_1, felica_lites_dump_1),
        (felica_lites_data_2, felica_lites_dump_2),
    ])
    def test_dump(self, tag, data, dump):
        tag.clf.exchange.side_effect = data
        assert tag.dump() == dump

    def test_protect_with_password_too_short(self, tag):
        with pytest.raises(ValueError) as excinfo:
            tag.protect("abc")
        assert str(excinfo.value) == "password must be at least 16 byte"

    def test_protect_from_negative_block_value(self, tag):
        with pytest.raises(ValueError) as excinfo:
            tag.protect("0123456789abcdef", protect_from=-1)
        assert str(excinfo.value) == "protect_from can not be negative"

    def test_protect_when_key_change_is_disabled(self, tag):
        tag.clf.exchange.side_effect = [
            HEX("1d 07 0102030405060708 0000 01"
                "FF FF 00 01  07 00 00 00  00 00 00 00  00 00 00 00"),
        ]
        assert tag.protect("0123456789abcdef") is False
        tag.clf.exchange.assert_called_with(
            HEX('10 06 0102030405060708 010b00 018088'), 0.3093504)

    def test_protect_when_authentication_needed(self, tag):
        tag.clf.exchange.side_effect = [
            HEX("1d 07 0102030405060708 0000 01"
                "FF FF 00 01  07 01 00 00  00 00 00 00  00 00 00 00"),
        ]
        assert tag.protect("0123456789abcdef") is False
        tag.clf.exchange.assert_called_with(
            HEX('10 06 0102030405060708 010b00 018088'), 0.3093504)

    def test_protect_ndef_tag_readonly(self, tag):
        commands = [
            (HEX('10 06 0102030405060708 010b00 018088'), 0.3093504),   # 1
            (HEX('10 06 0102030405060708 010b00 018086'), 0.3093504),   # 2
            (HEX('20 08 0102030405060708 010900 018086'  # write CKV    # 3
                 '01000000 00000000 00000000 00000000'), 0.3093504),
            (HEX('20 08 0102030405060708 010900 018087'  # write CK     # 4
                 '37363534 33323130 66656463 62613938'), 0.3093504),
            # authenticate_1
            (HEX('20 08 0102030405060708 010900 018080'  # write RC     # 5
                 '07060504 03020100 0f0e0d0c 0b0a0908'), 0.3093504),
            (HEX('12 06 0102030405060708 010b00 0280828081'),           # 6
             0.46402560000000004),  # read ID, MAC
            # authenticate_2 - write_with_mac
            (HEX('10 06 0102030405060708 010b00 018090'), 0.3093504),   # 7
            (HEX('32 08 0102030405060708 010900 0280928091'             # 8
                 '01000000 00000000 00000000 00000000'
                 '17c19e3b bdc3e8bd 00feff00 00000000'),
             0.46402560000000004),  # write STATE, MAC_A
            (HEX('12 06 0102030405060708 010b00 0280928081'),           # 9
             0.46402560000000004),  # read_with_mac STATE
            # read ndef
            (HEX('06 00 12fc 0000'), 0.003625),  # poll for ndef        # 10
            (HEX('12 06 0102030405060708 010b00 0280008081'),           # 11
             0.46402560000000004),  # read_with_mac Block 0
            # read MC for ndef attribute rw flag
            (HEX('10 06 0102030405060708 010b00 018088'), 0.3093504),   # 12
            # read and write ndef attribute data
            (HEX('10 06 0102030405060708 010b00 018000'), 0.3093504),   # 13
            (HEX('20 08 0102030405060708 010900 018000'                 # 14
                 '10040100 03000000 00000000 00000018'), 0.3093504),
            # write memory configuration
            (HEX('20 08 0102030405060708 010900 018088'  # write MC     # 15
                 'ffff0001 0701ff3f ff3fff3f 00000000'), 0.3093504),
        ]
        responses = [
            HEX('1d 07 0102030405060708 0000 01'  # read MC             # 1
                'FF FF FF 01  07 00 00 00  00 00 00 00  00 00 00 00'),
            HEX('1d 07 0102030405060708 0000 01'  # read CKV            # 2
                '00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00'),
            HEX('0c 09 0102030405060708 0000'),   # write CKV           # 3
            HEX('0c 09 0102030405060708 0000'),   # write CK            # 4
            # authenticate_1
            HEX('0c 09 0102030405060708 0000'),   # write RC            # 5
            HEX('2d 07 0102030405060708 0000 02'  # read ID, MAC        # 6
                '01 02 03 04  05 06 07 08  00 00 00 00  00 00 00 00'
                '91 ae c5 b6  d9 b3 b1 2d  00 00 00 00  00 00 00 00'),
            # authenticate_2
            HEX('1d 07 0102030405060708 0000 01'  # read WCNT           # 7
                '00 FE FF 00  00 00 00 00  00 00 00 00  00 00 00 00'),
            HEX('0c 09 0102030405060708 0000'),   # write STATE, MAC_A  # 8
            HEX('2d 07 0102030405060708 0000 02'  # read STATE, MAC     # 9
                '01 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00'
                'bd 73 eb 72  94 a0 02 79  00 00 00 00  00 00 00 00'),
            HEX("12 01 0102030405060708 00F1FFFFFFFFFFFF"),  # polling  # 10
            HEX('2d 07 0102030405060708 0000 02'  # read attribute data # 11
                '10 04 01 00  03 00 00 00  00 00 01 00  00 00 00 19'
                'a6 22 c3 37  a4 e4 42 71  00 00 00 00  00 00 00 00'),
            HEX('1d 07 0102030405060708 0000 01'  # read MC             # 12
                'FF FF FF 01  07 00 00 00  00 00 00 00  00 00 00 00'),
            HEX('1d 07 0102030405060708 0000 01'  # read attribute data # 13
                '10 04 01 00  03 00 00 00  00 00 01 00  00 00 00 19'),
            HEX('0c 09 0102030405060708 0000'),   # write Block 0       # 14
            HEX('0c 09 0102030405060708 0000'),   # write MC            # 15
        ]
        tag.clf.exchange.side_effect = responses
        assert tag.protect("0123456789abcdef", read_protect=True) is True
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

    def test_protect_unformatted_tag(self, tag):
        commands = [
            (HEX('10 06 0102030405060708 010b00 018088'), 0.3093504),   # 1
            (HEX('10 06 0102030405060708 010b00 018086'), 0.3093504),   # 2
            (HEX('20 08 0102030405060708 010900 018086'  # write CKV    # 3
                 '01000000 00000000 00000000 00000000'), 0.3093504),
            (HEX('20 08 0102030405060708 010900 018087'  # write CK     # 4
                 '37363534 33323130 66656463 62613938'), 0.3093504),
            # authenticate_1
            (HEX('20 08 0102030405060708 010900 018080'  # write RC     # 5
                 '07060504 03020100 0f0e0d0c 0b0a0908'), 0.3093504),
            (HEX('12 06 0102030405060708 010b00 0280828081'),           # 6
             0.46402560000000004),  # read ID, MAC
            # authenticate_2 - write_with_mac
            (HEX('10 06 0102030405060708 010b00 018090'), 0.3093504),   # 7
            (HEX('32 08 0102030405060708 010900 0280928091'             # 8
                 '01000000 00000000 00000000 00000000'
                 '17c19e3b bdc3e8bd 00feff00 00000000'),
             0.46402560000000004),  # write STATE, MAC_A
            (HEX('12 06 0102030405060708 010b00 0280928081'),           # 9
             0.46402560000000004),  # read_with_mac STATE
            # read ndef
            (HEX('06 00 12fc 0000'), 0.003625),  # poll for ndef        # 10
            (HEX('12 06 0102030405060708 010b00 0280008081'),           # 11
             0.46402560000000004),  # read_with_mac Block 0
            # read MC for ndef attribute rw flag
            (HEX('10 06 0102030405060708 010b00 018088'), 0.3093504),   # 12
            # write memory configuration
            (HEX('20 08 0102030405060708 010900 018088'  # write MC     # 13
                 'ffff0001 07010000 ff3fff3f 00000000'), 0.3093504),
        ]
        responses = [
            HEX('1d 07 0102030405060708 0000 01'  # read MC             # 1
                'FF FF FF 01  07 00 00 00  00 00 00 00  00 00 00 00'),
            HEX('1d 07 0102030405060708 0000 01'  # read CKV            # 2
                '00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00'),
            HEX('0c 09 0102030405060708 0000'),   # write CKV           # 3
            HEX('0c 09 0102030405060708 0000'),   # write CK            # 4
            # authenticate_1
            HEX('0c 09 0102030405060708 0000'),   # write RC            # 5
            HEX('2d 07 0102030405060708 0000 02'  # read ID, MAC        # 6
                '01 02 03 04  05 06 07 08  00 00 00 00  00 00 00 00'
                '91 ae c5 b6  d9 b3 b1 2d  00 00 00 00  00 00 00 00'),
            # authenticate_2
            HEX('1d 07 0102030405060708 0000 01'  # read WCNT           # 7
                '00 FE FF 00  00 00 00 00  00 00 00 00  00 00 00 00'),
            HEX('0c 09 0102030405060708 0000'),   # write STATE, MAC_A  # 8
            HEX('2d 07 0102030405060708 0000 02'  # read STATE, MAC     # 9
                '01 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00'
                'bd 73 eb 72  94 a0 02 79  00 00 00 00  00 00 00 00'),
            HEX("12 01 0102030405060708 00F1FFFFFFFFFFFF"),  # polling  # 10
            HEX('2d 07 0102030405060708 0000 02'  # read attribute data # 11
                '00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00'
                'cc 97 f1 b9  7b 8b bc 79  00 00 00 00  00 00 00 00'),
            HEX('1d 07 0102030405060708 0000 01'  # read MC             # 12
                'FF FF FF 01  07 00 00 00  00 00 00 00  00 00 00 00'),
            HEX('0c 09 0102030405060708 0000'),   # write MC            # 13
        ]
        tag.clf.exchange.side_effect = responses
        assert tag.protect("0123456789abcdef") is True
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

    def test_protect_with_wrong_password(self, tag):
        commands = [
            (HEX('10 06 0102030405060708 010b00 018088'), 0.3093504),   # 1
            (HEX('10 06 0102030405060708 010b00 018086'), 0.3093504),   # 2
            (HEX('20 08 0102030405060708 010900 018086'  # write CKV    # 3
                 '01000000 00000000 00000000 00000000'), 0.3093504),
            (HEX('20 08 0102030405060708 010900 018087'  # write CK     # 4
                 '38373635 34333231 66656463 62613039'), 0.3093504),
            # authenticate_1
            (HEX('20 08 0102030405060708 010900 018080'  # write RC     # 5
                 '07060504 03020100 0f0e0d0c 0b0a0908'), 0.3093504),
            (HEX('12 06 0102030405060708 010b00 0280828081'),           # 6
             0.46402560000000004),  # read ID, MAC
        ]
        responses = [
            HEX('1d 07 0102030405060708 0000 01'  # read MC             # 1
                'FF FF FF 01  07 00 00 00  00 00 00 00  00 00 00 00'),
            HEX('1d 07 0102030405060708 0000 01'  # read CKV            # 2
                '00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00'),
            HEX('0c 09 0102030405060708 0000'),   # write CKV           # 3
            HEX('0c 09 0102030405060708 0000'),   # write CK            # 4
            # authenticate_1
            HEX('0c 09 0102030405060708 0000'),   # write RC            # 5
            HEX('2d 07 0102030405060708 0000 02'  # read ID, MAC        # 6
                '01 02 03 04  05 06 07 08  00 00 00 00  00 00 00 00'
                '91 ae c5 b6  d9 b3 b1 2d  00 00 00 00  00 00 00 00'),
        ]
        tag.clf.exchange.side_effect = responses
        assert tag.protect("1234567890abcdef") is False
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

    def test_mutual_authentication_error(self, tag):
        commands = [
            # authenticate_1
            (HEX('20 08 0102030405060708 010900 018080'  # write RC     # 5
                 '07060504 03020100 0f0e0d0c 0b0a0908'), 0.3093504),
            (HEX('12 06 0102030405060708 010b00 0280828081'),           # 6
             0.46402560000000004),  # read ID, MAC
            # authenticate_2 - write_with_mac
            (HEX('10 06 0102030405060708 010b00 018090'), 0.3093504),   # 7
            (HEX('32 08 0102030405060708 010900 0280928091'             # 8
                 '01000000 00000000 00000000 00000000'
                 '17c19e3b bdc3e8bd 00feff00 00000000'),
             0.46402560000000004),  # write STATE, MAC_A
            (HEX('12 06 0102030405060708 010b00 0280928081'),           # 9
             0.46402560000000004),  # read_with_mac STATE
        ]
        responses = [
            # authenticate_1
            HEX('0c 09 0102030405060708 0000'),   # write RC            # 5
            HEX('2d 07 0102030405060708 0000 02'  # read ID, MAC        # 6
                '01 02 03 04  05 06 07 08  00 00 00 00  00 00 00 00'
                '91 ae c5 b6  d9 b3 b1 2d  00 00 00 00  00 00 00 00'),
            # authenticate_2
            HEX('1d 07 0102030405060708 0000 01'  # read WCNT           # 7
                '00 FE FF 00  00 00 00 00  00 00 00 00  00 00 00 00'),
            HEX('0c 09 0102030405060708 0000'),   # write STATE, MAC_A  # 8
            HEX('2d 07 0102030405060708 0000 02'  # read STATE, MAC     # 9
                '00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00'
                'cc 97 f1 b9  7b 8b bc 79  00 00 00 00  00 00 00 00'),
        ]
        tag.clf.exchange.side_effect = responses
        assert tag.authenticate(b"0123456789abcdef") is False
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

    def test_write_with_mac_wrong_data_size(self, tag):
        with pytest.raises(ValueError) as excinfo:
            tag.write_with_mac(bytearray(15), 0)
        assert str(excinfo.value) == "data must be 16 octets"

    def test_write_with_mac_block_arg_not_int(self, tag):
        with pytest.raises(ValueError) as excinfo:
            tag.write_with_mac(bytearray(16), '0')
        assert str(excinfo.value) == "block number must be int"

    def test_write_with_mac_not_authenticated(self, tag):
        with pytest.raises(RuntimeError) as excinfo:
            tag.write_with_mac(bytearray(16), 0)
        assert str(excinfo.value) == "tag must be authenticated first"


###############################################################################
#
# FeliCa Plug
#
###############################################################################
class TestFelicaPlug:
    @pytest.mark.parametrize("ic_code, product", [
        ('E0', "FeliCa Plug (RC-S926)"),
        ('E1', "FeliCa Link (RC-S730) Plug Mode"),
    ])
    def test_init(self, ic_code, product):
        sensf_res = HEX("01 0102030405060708 00%sFFFFFFFFFFFF 0000" % ic_code)
        target = nfc.clf.RemoteTarget("212F", sensf_res=sensf_res)
        tag = nfc.tag.activate(clf, target)
        assert isinstance(tag, nfc.tag.tt3_sony.FelicaPlug)
        assert tag.product == product

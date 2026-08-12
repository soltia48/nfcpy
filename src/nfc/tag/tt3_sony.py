# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2014, 2017 Stephen Tiedemann <stephen.tiedemann@gmail.com>
#
# Licensed under the EUPL, Version 1.1 or - as soon they
# will be approved by the European Commission - subsequent
# versions of the EUPL (the "Licence");
# You may not use this work except in compliance with the
# Licence.
# You may obtain a copy of the Licence at:
#
# https://joinup.ec.europa.eu/software/page/eupl
#
# Unless required by applicable law or agreed to in
# writing, software distributed under the Licence is
# distributed on an "AS IS" basis,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied.
# See the Licence for the specific language governing
# permissions and limitations under the Licence.
# -----------------------------------------------------------------------------
import nfc.tag
from . import tt3

from dataclasses import dataclass
import hmac
import os
import struct
from binascii import hexlify
from Crypto.Cipher import AES, DES, DES3
from Crypto.Hash import CMAC
from struct import pack, unpack
from typing import (
    Dict, List, NoReturn, Optional, Sequence, Tuple, TypedDict, Union)
import itertools

import logging
log = logging.getLogger(__name__)

Octets = Union[bytes, bytearray, memoryview]
SecureSessionScheme = str
AreaCodeRange = Tuple[int, int]
ServiceVersion = Union[int, Tuple[int, int]]

# Fixed part of a secure read response payload: both status flags and the
# block count, ahead of the block data itself.
SECURE_READ_RESPONSE_OVERHEAD = 1 + 1 + 1

# Transaction number and transaction ID of a DES secure messaging header.
DES_SECURE_HEADER_SIZE = 2 + 6


def _padded_to_des_block_size(length: int) -> int:
    """Round up the way PKCS#7 padding does.

    Between one and eight byte are always appended, so an already aligned
    length grows by a full block.

    """
    return (length // 8 + 1) * 8


def _max_secure_read_block_count() -> int:
    """Most blocks a single DES Read can return.

    A secure read is bounded by its response, not by its command: the
    request stays small however many blocks it names, so an over-long one
    would be sent and then be unanswerable. The response frame is ``LEN(1) +
    response code(1) + E(txn(2) + txid(6) + SF1(1) + SF2(1) + n(1) + 16n) +
    MAC(8)`` where ``E(..)`` is PKCS#7 padded to whole DES blocks.

    """
    blocks = 0
    while True:
        length = 2 + _padded_to_des_block_size(
            DES_SECURE_HEADER_SIZE + SECURE_READ_RESPONSE_OVERHEAD
            + (blocks + 1) * 16) + 8
        if length > tt3.MAX_PACKET_LEN:
            return blocks
        blocks += 1


def _max_secure_read_v2_block_count() -> int:
    """Most blocks a single AES-128 Read v2 can return.

    The v2 scheme encrypts with an OFB stream rather than a block cipher, so
    its response frame carries no padding: ``LEN(1) + response code(1) +
    counter(2) + SF1(1) + SF2(1) + n(1) + 16n + MAC(8)``. That leaves room
    for one more block than the DES scheme.

    """
    return (tt3.MAX_PACKET_LEN
            - (2 + 2 + SECURE_READ_RESPONSE_OVERHEAD + 8)) // 16


def status_flag1_description(status_flag1: int) -> str:
    """Describe status flag 1 of a card response.

    A value other than 0x00 (normal completion) and 0xFF (the error is not
    associated with a particular list entry) points at the service code list
    or block list entry that failed. The specification defines two product
    dependent encodings for that and the response carries no indication of
    which one a card uses, so both readings are given: the byte may be the
    1-based position in the list, or a bit map in which bit *n* (for *n* in
    0..6) means the *(n+1)*-th or *(n+9)*-th entry and bit 7 the 8th entry.

    """
    if status_flag1 == 0x00:
        return "normal completion"
    if status_flag1 == 0xFF:
        return "error not associated with a specific list entry"
    positions = list()
    for bit in range(8):
        if status_flag1 & (1 << bit):
            positions.append(bit + 1)
            if bit <= 6:
                positions.append(bit + 9)
    return ("error at list position {0} (ordinal encoding) or {1} (bit "
            "encoding)".format(status_flag1,
                               "/".join(map(str, sorted(positions)))))


class OptionVersion(TypedDict):
    major: int
    minor: int
    patch: int


@dataclass
class SpecificationVersion:
    format_version: int
    basic_version: OptionVersion
    option_versions: List[OptionVersion]

    def _option_version(self, index: int) -> Optional[OptionVersion]:
        if 0 <= index < len(self.option_versions):
            return self.option_versions[index]
        return None

    @property
    def des_option_version(self) -> Optional[OptionVersion]:
        return self._option_version(0)

    @property
    def special_option_version(self) -> Optional[OptionVersion]:
        return self._option_version(1)

    @property
    def extended_overlap_option_version(self) -> Optional[OptionVersion]:
        return self._option_version(2)

    @property
    def value_limited_purse_service_option_version(
            self) -> Optional[OptionVersion]:
        return self._option_version(3)

    @property
    def communication_with_mac_option_version(self) -> Optional[OptionVersion]:
        return self._option_version(4)

    @property
    def random_id_option_version(self) -> Optional[OptionVersion]:
        return self._option_version(5)


# Backward-compatible aliases for the previous TypedDict names.
SpecificationVersionInfo = SpecificationVersion
SpecVersionInfo = SpecificationVersion


class NodePropertyValueLimitedPurseService(TypedDict):
    enabled: bool
    upper_limit: int
    lower_limit: int
    generation_number: int


class NodePropertyMacCommunication(TypedDict):
    enabled: bool


NodeProperty = Union[
    NodePropertyValueLimitedPurseService,
    NodePropertyMacCommunication,
]


def zeroize(*values: Optional[Octets]) -> None:
    """Overwrite secret byte buffers in place.

    Only a :class:`bytearray` can be cleared, anything else is ignored.
    This bounds how long key material lives, it does not eliminate it:
    Python copies freely and a :class:`bytes` object cannot be overwritten
    at all, so every copy that was made before is untouched and the
    interpreter may keep further copies out of reach. Swap and core dumps
    still need handling at the operating system level.

    """
    for value in values:
        if isinstance(value, bytearray):
            for i in range(len(value)):
                value[i] = 0


def _redacted(value: Octets) -> str:
    return "<{0} bytes redacted>".format(len(value))


@dataclass
class DesSecureSessionCredentials:
    session_key: Octets

    def __post_init__(self) -> None:
        self.session_key = bytearray(self.session_key)
        if len(self.session_key) != 8:
            raise ValueError("session_key must be 8 bytes")

    def __repr__(self) -> str:
        # The session key must not reach a log; one debug log of a session
        # object would otherwise write it into an application log file.
        return "DesSecureSessionCredentials(session_key={0})".format(
            _redacted(self.session_key))

    def clone(self) -> "DesSecureSessionCredentials":
        return DesSecureSessionCredentials(bytearray(self.session_key))

    def zeroize(self) -> None:
        """Overwrite the session key in place."""
        zeroize(self.session_key)


@dataclass
class Aes128SecureSessionCredentials:
    encryption_key: Octets
    mac_key: Octets
    challenge_3c: Octets

    def __post_init__(self) -> None:
        self.encryption_key = bytearray(self.encryption_key)
        self.mac_key = bytearray(self.mac_key)
        self.challenge_3c = bytearray(self.challenge_3c)
        if len(self.encryption_key) != 16 or len(self.mac_key) != 16:
            raise ValueError("encryption_key and mac_key must be 16 bytes")
        if len(self.challenge_3c) != 4:
            raise ValueError("challenge_3c must be 4 bytes")

    def __repr__(self) -> str:
        # The session keys must not reach a log. The challenge_3c value is
        # sent by the card in the clear, so it stays visible for debugging.
        return ("Aes128SecureSessionCredentials(encryption_key={0}, "
                "mac_key={1}, challenge_3c={2})".format(
                    _redacted(self.encryption_key), _redacted(self.mac_key),
                    hexlify(self.challenge_3c).decode()))

    def clone(self) -> "Aes128SecureSessionCredentials":
        return Aes128SecureSessionCredentials(
            bytearray(self.encryption_key),
            bytearray(self.mac_key),
            bytearray(self.challenge_3c),
        )

    def zeroize(self) -> None:
        """Overwrite the session keys in place."""
        zeroize(self.encryption_key, self.mac_key)


SecureSessionCredentials = Union[
    DesSecureSessionCredentials, Aes128SecureSessionCredentials]


@dataclass
class AuthenticatedContext:
    transaction_number: int
    transaction_id: Octets
    credentials: SecureSessionCredentials
    nodes: Sequence[int] = ()
    """The addressable nodes of the session, in Authentication1 order.

    A block list element names its target by position in this list, so
    anything that has to identify a node of the live session, such as
    :meth:`FelicaStandard.change_keys` naming the node whose key it
    replaces, depends on the order being preserved. For DES this is the
    *services* list of Authentication1, because the area list only scopes
    the key chain and is not addressable; for v2 it is the node list.

    A context built by hand, for instance by a relay that holds the keys,
    should pass the same list it authenticated with. Leaving it empty only
    means that node lookups fail, never that a wrong node is used.

    """

    def __post_init__(self) -> None:
        if not isinstance(self.transaction_number, int):
            raise ValueError("transaction_number must be an integer")
        if not 0 <= self.transaction_number <= 0xFFFF:
            raise ValueError("transaction_number must be in range 0..65535")
        self.transaction_id = bytearray(self.transaction_id)
        if len(self.transaction_id) != 6:
            raise ValueError("transaction_id must be 6 bytes")
        self.nodes = [int(node) for node in self.nodes]
        if any(not 0 <= node <= 0xFFFF for node in self.nodes):
            raise ValueError("node codes must be 16-bit integers")
        if isinstance(self.credentials, (
                DesSecureSessionCredentials, Aes128SecureSessionCredentials)):
            return
        raise ValueError(
            "credentials must be DES or AES128 secure session credentials")

    @property
    def scheme(self) -> SecureSessionScheme:
        if isinstance(self.credentials, DesSecureSessionCredentials):
            return "des"
        return "aes128"

    def node_index(self, node: int) -> Optional[int]:
        """Return the position of *node* in the session's node list.

        This is what the service list index of a block list element
        selects. :const:`None` is returned if the session was not opened
        against that node.

        """
        try:
            return list(self.nodes).index(int(node))
        except ValueError:
            return None

    def clone(self) -> "AuthenticatedContext":
        if isinstance(self.credentials, DesSecureSessionCredentials):
            credentials = self.credentials.clone()
        else:
            credentials = self.credentials.clone()
        return AuthenticatedContext(
            transaction_number=self.transaction_number,
            transaction_id=bytearray(self.transaction_id),
            credentials=credentials,
            nodes=list(self.nodes),
        )

    def increment_transaction_number(self) -> None:
        if self.transaction_number >= 0xFFFF:
            raise ValueError("secure session transaction number overflow")
        self.transaction_number += 1

    def zeroize(self) -> None:
        """Overwrite the session keys in place.

        The transaction number, the transaction ID and the node codes are
        not secret and are left alone.

        """
        self.credentials.zeroize()


class ChangeKeyParam(TypedDict):
    node: int
    parent_key: Octets
    new_key: Octets
    old_key: Octets
    new_key_version: int


def activate(clf, target) -> Optional[tt3.Type3Tag]:
    # http://www.sony.net/Products/felica/business/tech-support/list.html
    ic_code = target.sensf_res[10]
    if ic_code in FelicaLite.IC_CODE_MAP.keys():
        return FelicaLite(clf, target)
    if ic_code in FelicaLiteS.IC_CODE_MAP.keys():
        return FelicaLiteS(clf, target)
    if ic_code in FelicaStandard.IC_CODE_MAP.keys():
        return FelicaStandard(clf, target)
    if ic_code in FelicaMobile.IC_CODE_MAP.keys():
        return FelicaMobile(clf, target)
    if ic_code in FelicaPlug.IC_CODE_MAP.keys():
        return FelicaPlug(clf, target)
    return None


class FelicaStandard(tt3.Type3Tag):
    """Standard FeliCa is a range of FeliCa OS based card products with a
    flexible file system that supports multiple applications and
    services on the same card. Services can individually be protected
    with a card key and all communication with protected services is
    encrypted.

    """
    IC_CODE_MAP = {
        # IC    IC-NAME    NBR NBW
        0x00: ("RC-S830",    8,  8),  # RC-S831/833
        0x01: ("RC-S915",   12,  8),  # RC-S860/862/863/864/891
        0x02: ("RC-S919",    1,  1),  # RC-S890
        0x08: ("RC-S952",   12,  8),
        0x09: ("RC-S953",   12,  8),
        0x0B: ("RC-S???",    1,  1),  # new suica
        0x0C: ("RC-S954",   12,  8),
        0x0D: ("RC-S960",   12, 10),  # RC-S880/889
        0x20: ("RC-S962",   12, 10),  # RC-S885/888/892/893
        0x32: ("RC-SA00/1",  1,  1),  # AES chip
        0x35: ("RC-SA00/2",  1,  1),
    }
    # Command codes for FeliCa Standard commands.
    REQUEST_SERVICE_CMD = 0x02
    REQUEST_RESPONSE_CMD = 0x04
    SEARCH_SERVICE_CODE_CMD = 0x0A
    REQUEST_SYSTEM_CODE_CMD = 0x0C
    REQUEST_BLOCK_INFORMATION_CMD = 0x0E
    AUTHENTICATION1_CMD = 0x10
    AUTHENTICATION2_CMD = 0x12
    READ_CMD = 0x14
    WRITE_CMD = 0x16
    REQUEST_CODE_LIST_CMD = 0x1A
    REQUEST_BLOCK_INFORMATION_EX_CMD = 0x1E
    SET_PARAMETER_CMD = 0x20
    GET_CONTAINER_ISSUE_INFORMATION_CMD = 0x22
    GET_AREA_INFORMATION_CMD = 0x24
    GET_NODE_PROPERTY_CMD = 0x28
    GET_CONTAINER_PROPERTY_CMD = 0x2E
    REQUEST_SERVICE_V2_CMD = 0x32
    GET_SYSTEM_STATUS_CMD = 0x38
    REQUEST_PRODUCT_INFORMATION_CMD = 0x3A
    REQUEST_SPECIFICATION_VERSION_CMD = 0x3C
    RESET_MODE_CMD = 0x3E
    AUTHENTICATION1_V2_CMD = 0x40
    AUTHENTICATION2_V2_CMD = 0x42
    READ_V2_CMD = 0x44
    WRITE_V2_CMD = 0x46
    GET_CONTAINER_ID_CMD = 0x70
    REGISTER_ISSUE_ID_CMD = 0x80
    REGISTER_AREA_CMD = 0x82
    REGISTER_SERVICE_CMD = 0x84
    CHANGE_SYSTEM_BLOCK_CMD = 0x8E

    # PMm timing slots used by the currently implemented commands.
    REQUEST_SERVICE_PMMSLOT = 2
    REQUEST_RESPONSE_PMMSLOT = 3
    SEARCH_SERVICE_CODE_PMMSLOT = 3
    REQUEST_SYSTEM_CODE_PMMSLOT = 3
    REQUEST_BLOCK_INFORMATION_PMMSLOT = 2
    AUTHENTICATION1_PMMSLOT = 4
    AUTHENTICATION2_PMMSLOT = 4
    READ_PMMSLOT = 5
    WRITE_PMMSLOT = 6
    REQUEST_CODE_LIST_PMMSLOT = 2
    REQUEST_BLOCK_INFORMATION_EX_PMMSLOT = 2
    SET_PARAMETER_PMMSLOT = 7
    GET_CONTAINER_ISSUE_INFORMATION_PMMSLOT = 7
    GET_AREA_INFORMATION_PMMSLOT = 3
    GET_NODE_PROPERTY_PMMSLOT = 2
    GET_CONTAINER_PROPERTY_PMMSLOT = 7
    REQUEST_SERVICE_V2_PMMSLOT = 2
    GET_SYSTEM_STATUS_PMMSLOT = 3
    REQUEST_PRODUCT_INFORMATION_PMMSLOT = 7
    REQUEST_SPECIFICATION_VERSION_PMMSLOT = 3
    RESET_MODE_PMMSLOT = 3
    REGISTRATION_PMMSLOT = 7
    GET_CONTAINER_ID_PMMSLOT = 7

    NODE_PROPERTY_VALUE_LIMITED_PURSE_SERVICE = 0x00
    NODE_PROPERTY_MAC_COMMUNICATION = 0x01

    REQUEST_SERVICE_V2_DUAL_KEYS_AES128 = 0x41
    REQUEST_SERVICE_V2_DUAL_KEYS_AES_CMAC = 0x43
    SECURE_SCHEME_DES = "des"
    SECURE_SCHEME_AES128 = "aes128"
    V2_AES128_NODE_KEY_INIT = bytearray([
        0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80])
    V2_AES128_AUTH_CONTEXT_SUFFIX = b"\x01\x00"
    V2_AES128_DERIVE_ENCRYPTION_KEY_INPUT = bytearray([
        0x01, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00])
    V2_AES128_DERIVE_MAC_KEY_INPUT = bytearray([
        0x02, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00])

    # Upper bounds the specification puts on the list arguments of the
    # commands below. Sending more entries than the card accepts produces
    # an over-long frame, so the lists are checked before transmission.
    MAX_SERVICE_CODES = 0x20
    MAX_NODE_CODES = 0x20
    MAX_NODE_PROPERTY_CODES = 0x10

    # Largest block count a command or a response can state. This is the
    # width of the block count field, not a limit on how many blocks a card
    # accepts; the maximum is left to each product and every product is
    # bounded by what a single 255 byte packet holds. A write is caught
    # exactly by that packet limit when the frame is built, because its
    # ceiling depends on whether the block list elements are two or three
    # byte wide. A read must be checked separately, as it is bounded by its
    # response while the command itself stays small.
    MAX_BLOCK_COUNT = 0xFF
    MAX_READ_WITHOUT_ENCRYPTION_BLOCK_COUNT = \
        tt3.MAX_READ_WITHOUT_ENCRYPTION_BLOCK_COUNT
    MAX_SECURE_READ_BLOCK_COUNT = _max_secure_read_block_count()
    MAX_SECURE_READ_V2_BLOCK_COUNT = _max_secure_read_v2_block_count()

    TIMEOUT_UNIT = 302E-6
    MIN_TIMEOUT = 0.002

    def __init__(self, clf, target):
        super(FelicaStandard, self).__init__(clf, target)
        self._product = "FeliCa Standard ({0})".format(
            self.IC_CODE_MAP[self.pmm[1]][0])
        self._authenticated_context = \
            None  # type: Optional[AuthenticatedContext]

    def _timing_params(self, pmm_slot: int) -> Tuple[int, int, int]:
        pmm_byte = self.pmm[pmm_slot]
        return pmm_byte & 7, pmm_byte >> 3 & 7, pmm_byte >> 6

    def _base_timeout(
            self, pmm_slot: int, enforce_min: bool = False) -> float:
        a, _, e = self._timing_params(pmm_slot)
        timeout = self.TIMEOUT_UNIT * (a + 1) * 4**e
        return max(timeout, self.MIN_TIMEOUT) if enforce_min else timeout

    def _scaled_timeout(
            self, pmm_slot: int, units: int,
            enforce_min: bool = False) -> float:
        a, b, e = self._timing_params(pmm_slot)
        timeout = self.TIMEOUT_UNIT * ((b + 1) * units + a + 1) * 4**e
        return max(timeout, self.MIN_TIMEOUT) if enforce_min else timeout

    def _send_standard_command(
            self, cmd_code: int, cmd_data: Octets,
            timeout: float) -> bytearray:
        return self.send_cmd_recv_rsp(
            cmd_code, cmd_data, timeout, check_status=False)

    @staticmethod
    def _raise_data_size_error() -> NoReturn:
        log.debug("insufficient data received from tag")
        raise tt3.Type3TagCommandError(tt3.DATA_SIZE_ERROR)

    @classmethod
    def _validate_exact_length(cls, data: Octets, size: int) -> None:
        if len(data) != size:
            cls._raise_data_size_error()

    @classmethod
    def _validate_min_length(cls, data: Octets, size: int) -> None:
        if len(data) < size:
            cls._raise_data_size_error()

    @staticmethod
    def _raise_status_flag_error(
            status_flag1: int, status_flag2: int) -> NoReturn:
        log.debug("tag returned error status {0:02x}{1:02x} ({2})".format(
            status_flag1, status_flag2,
            status_flag1_description(status_flag1)))
        raise tt3.Type3TagCommandError(status_flag1 << 8 | status_flag2)

    @classmethod
    def _parse_status_flags(
            cls, data: Octets, min_length: int = 2) -> Tuple[int, int]:
        cls._validate_min_length(data, min_length)
        return data[0], data[1]

    @classmethod
    def _validate_status_flags(
            cls, data: Octets, min_length: int = 2) -> Tuple[int, int]:
        """Decide success or failure from a response's status flags.

        Status flag 1 is the authority: 0x00 says that the card processed
        the command normally and status flag 2 only details why a failure
        happened. Status flag 2 must therefore not be second-guessed when
        flag 1 reports normal completion. The memory rewrite count warning
        (status flag 2 = 0x71) is raised *after* the write has been
        performed and some products pair it with status flag 1 = 0x00;
        rejecting such a response would report a completed write as a
        failure and invite the caller to retry it. A non-zero flag 2 is
        logged so that the warning is not silently dropped.

        """
        status_flag1, status_flag2 = cls._parse_status_flags(
            data, min_length=min_length)
        if status_flag1 != 0:
            cls._raise_status_flag_error(status_flag1, status_flag2)
        if status_flag2 != 0:
            log.warning(
                "command completed normally but reported status flag 2 "
                "{0:02x}".format(status_flag2))
        return status_flag1, status_flag2

    @staticmethod
    def _parse_option_version(option_bytes: Octets) -> OptionVersion:
        return {
            "major": option_bytes[1] & 0x0F,
            "minor": (option_bytes[0] >> 4) & 0x0F,
            "patch": option_bytes[0] & 0x0F,
        }

    @staticmethod
    def _raise_protocol_error(message: str) -> NoReturn:
        log.debug(message)
        raise tt3.Type3TagCommandError(nfc.tag.PROTOCOL_ERROR)

    @staticmethod
    def _raise_authentication_error(message: str) -> NoReturn:
        log.debug(message)
        raise RuntimeError(message)

    def _send_without_response_idm(
            self, cmd_code: int, cmd_data: Octets,
            timeout: float) -> bytearray:
        return self.send_cmd_recv_rsp(
            cmd_code, cmd_data, timeout, send_idm=False, check_status=False)

    def _send_command_with_idm_no_idm_response(
            self, cmd_code: int, payload: Octets, timeout: float) -> bytearray:
        return self._send_without_response_idm(
            cmd_code, self.idm + payload, timeout)

    @staticmethod
    def _to_bytes(data: Octets) -> bytes:
        return bytes(bytearray(data))

    @staticmethod
    def _xor_bytes(a: Octets, b: Octets) -> bytearray:
        return bytearray([x ^ y for x, y in zip(bytearray(a), bytearray(b))])

    @classmethod
    def _ct_eq(cls, a: Octets, b: Octets) -> bool:
        """Constant time equality for secret derived byte strings.

        Used for MAC tags and challenge responses, i.e. wherever a locally
        computed secret is compared against a value the card supplied. A
        plain comparison returns early at the first differing byte and thus
        tells an attacker how much of a forgery was already correct.

        """
        return hmac.compare_digest(cls._to_bytes(a), cls._to_bytes(b))

    @classmethod
    def _validate_list_length(
            cls, name: str, length: int, minimum: int, maximum: int) -> None:
        if not minimum <= length <= maximum:
            raise ValueError("{0} must contain between {1} and {2} entries"
                             .format(name, minimum, maximum))

    @staticmethod
    def _ceil_to_multiple(value: int, unit: int) -> int:
        return ((value + unit - 1) // unit) * unit

    @staticmethod
    def _pad_pkcs7(data: Octets, block_size: int) -> bytearray:
        data = bytearray(data)
        remainder = len(data) % block_size
        if remainder != 0:
            pad = block_size - remainder
            data.extend([pad] * pad)
        return data

    @classmethod
    def _encrypt_des_block(cls, data: Octets, key: Octets) -> bytearray:
        if len(data) != 8 or len(key) != 8:
            cls._raise_protocol_error(
                "DES block encrypt requires 8-byte block and key")
        cipher = DES.new(cls._to_bytes(key), DES.MODE_ECB)
        return bytearray(cipher.encrypt(cls._to_bytes(data)))

    @classmethod
    def _decrypt_des_block(cls, data: Octets, key: Octets) -> bytearray:
        if len(data) != 8 or len(key) != 8:
            cls._raise_protocol_error(
                "DES block decrypt requires 8-byte block and key")
        cipher = DES.new(cls._to_bytes(key), DES.MODE_ECB)
        return bytearray(cipher.decrypt(cls._to_bytes(data)))

    @classmethod
    def _normalize_3des_key(cls, key: Octets) -> bytes:
        key = bytearray(key)
        if len(key) in (16, 24):
            return cls._to_bytes(key)
        cls._raise_protocol_error("3DES key must be 16 or 24 bytes")

    @classmethod
    def _encrypt_3des_block_keys(
            cls, data: Octets, key1: Octets, key2: Octets,
            key3: Octets) -> bytearray:
        if (len(data) != 8 or len(key1) != 8 or
                len(key2) != 8 or len(key3) != 8):
            cls._raise_protocol_error(
                "3DES block encrypt requires 8-byte block and keys")
        key = cls._to_bytes(key1) + cls._to_bytes(key2) + cls._to_bytes(key3)
        cipher = DES3.new(key, DES3.MODE_ECB)
        return bytearray(cipher.encrypt(cls._to_bytes(data)))

    @classmethod
    def _decrypt_3des_block_keys(
            cls, data: Octets, key1: Octets, key2: Octets,
            key3: Octets) -> bytearray:
        if (len(data) != 8 or len(key1) != 8 or
                len(key2) != 8 or len(key3) != 8):
            cls._raise_protocol_error(
                "3DES block decrypt requires 8-byte block and keys")
        key = cls._to_bytes(key1) + cls._to_bytes(key2) + cls._to_bytes(key3)
        cipher = DES3.new(key, DES3.MODE_ECB)
        return bytearray(cipher.decrypt(cls._to_bytes(data)))

    @classmethod
    def _encrypt_3des_block(
            cls, data: Octets, key1: Octets, key2: Octets) -> bytearray:
        if len(data) != 8 or len(key1) != 8 or len(key2) != 8:
            cls._raise_protocol_error(
                "3DES block encrypt requires 8-byte block and keys")
        return cls._encrypt_3des_block_keys(data, key1, key2, key1)

    @classmethod
    def _decrypt_3des_block(
            cls, data: Octets, key1: Octets, key2: Octets) -> bytearray:
        if len(data) != 8 or len(key1) != 8 or len(key2) != 8:
            cls._raise_protocol_error(
                "3DES block decrypt requires 8-byte block and keys")
        return cls._decrypt_3des_block_keys(data, key1, key2, key1)

    @classmethod
    def _encrypt_des_cbc_zero_iv(cls, data: Octets, key: Octets) -> bytearray:
        if len(data) % 8 != 0 or len(key) != 8:
            cls._raise_protocol_error(
                "DES-CBC payload must be multiple of 8 bytes")
        cipher = DES.new(cls._to_bytes(key), DES.MODE_CBC, iv=b"\x00" * 8)
        return bytearray(cipher.encrypt(cls._to_bytes(data)))

    @classmethod
    def _decrypt_des_cbc_zero_iv(cls, data: Octets, key: Octets) -> bytearray:
        if len(data) % 8 != 0 or len(key) != 8:
            cls._raise_protocol_error(
                "DES-CBC payload must be multiple of 8 bytes")
        cipher = DES.new(cls._to_bytes(key), DES.MODE_CBC, iv=b"\x00" * 8)
        return bytearray(cipher.decrypt(cls._to_bytes(data)))

    @classmethod
    def _encrypt_3des_cbc(
            cls, data: Octets, key: Octets, iv: Octets) -> bytearray:
        if len(data) % 8 != 0 or len(iv) != 8:
            cls._raise_protocol_error(
                "3DES-CBC payload must be multiple of 8 bytes")
        cipher = DES3.new(
            cls._normalize_3des_key(key),
            DES3.MODE_CBC, iv=cls._to_bytes(iv))
        return bytearray(cipher.encrypt(cls._to_bytes(data)))

    @classmethod
    def _calculate_command_mac_des(
            cls, command_code: int, payload: Octets) -> bytearray:
        if len(payload) % 8 != 0:
            cls._raise_protocol_error(
                "secure command payload must be multiple of 8 bytes")
        total_length = 2 + len(payload) + 8
        if total_length > 255:
            cls._raise_protocol_error(
                "secure command payload exceeds maximum frame length")
        mac = bytearray(8)
        mac[0] = total_length
        mac[1] = command_code
        for i in range(0, len(payload), 8):
            mac = cls._encrypt_des_block(mac, payload[i:i+8])
        return mac

    @classmethod
    def _check_packet_mac_des(
            cls, data: Octets, expected_response_code: int) -> bool:
        if len(data) < 16 or len(data) % 8 != 0:
            return False
        payload, mac = data[:-8], data[-8:]
        x = bytearray(mac)
        for i in range(len(payload)-8, -1, -8):
            x = cls._decrypt_des_block(x, payload[i:i+8])
        # The MAC pre-image built by _calculate_command_mac_des is
        # [length, code, 0, 0, 0, 0, 0, 0], so a genuine MAC recovers all
        # eight bytes. Checking only length and code would drop the forgery
        # resistance from 64 to 16 bit and accept forged MACs that real
        # FeliCa hardware rejects, thus the reserved six bytes are checked
        # as well.
        expected = bytearray(8)
        expected[0] = (len(data) + 2) & 0xFF
        expected[1] = expected_response_code
        return cls._ct_eq(x, expected)

    @classmethod
    def _encrypt_secure_command_des(
            cls, command_code: int, payload: Octets,
            session_key: Octets) -> bytearray:
        padded = cls._pad_pkcs7(payload, 8)
        mac = cls._calculate_command_mac_des(command_code, padded)
        return cls._encrypt_des_cbc_zero_iv(padded + mac, session_key)

    @classmethod
    def _decrypt_secure_response_des(
            cls, response_code: int, expected_transaction_id: Octets,
            session_key: Octets,
            encrypted_payload: Octets) -> Tuple[int, bytearray]:
        plain = cls._decrypt_des_cbc_zero_iv(encrypted_payload, session_key)
        if cls._check_packet_mac_des(plain, response_code) is False:
            cls._raise_protocol_error(
                "secure response MAC verification failed")
        if len(plain) < 24:
            cls._raise_protocol_error("secure response payload too short")
        transaction_number = unpack("<H", plain[0:2])[0]
        transaction_id = plain[2:8]
        if transaction_id != expected_transaction_id:
            cls._raise_protocol_error(
                "secure response transaction ID mismatch")
        payload_with_pad = plain[8:-8]
        return transaction_number, payload_with_pad

    @staticmethod
    def _clone_authenticated_context(
            context: AuthenticatedContext) -> AuthenticatedContext:
        return context.clone()

    @staticmethod
    def _normalize_authenticated_context(
            context: AuthenticatedContext) -> AuthenticatedContext:
        if not isinstance(context, AuthenticatedContext):
            raise TypeError("context must be AuthenticatedContext")
        return context.clone()

    def _ensure_authenticated_context(self) -> AuthenticatedContext:
        if self._authenticated_context is None:
            self._raise_authentication_error("authentication required")
        return self._authenticated_context

    def _capture_secure_command_context(self) -> AuthenticatedContext:
        context = self._ensure_authenticated_context()
        try:
            context.increment_transaction_number()
        except ValueError as error:
            self._raise_protocol_error(str(error))
        return self._clone_authenticated_context(context)

    @classmethod
    def _encrypt_aes128_block(cls, data: Octets, key: Octets) -> bytearray:
        if len(data) != 16 or len(key) != 16:
            cls._raise_protocol_error(
                "AES block encrypt requires 16-byte block and key")
        cipher = AES.new(cls._to_bytes(key), AES.MODE_ECB)
        return bytearray(cipher.encrypt(cls._to_bytes(data)))

    @classmethod
    def _decrypt_aes128_block(cls, data: Octets, key: Octets) -> bytearray:
        if len(data) != 16 or len(key) != 16:
            cls._raise_protocol_error(
                "AES block decrypt requires 16-byte block and key")
        cipher = AES.new(cls._to_bytes(key), AES.MODE_ECB)
        return bytearray(cipher.decrypt(cls._to_bytes(data)))

    @classmethod
    def _calculate_mac_v2_aes128(
            cls, iv: Octets, payload: Octets, mac_key: Octets) -> bytearray:
        if len(iv) != 16 or len(mac_key) != 16:
            cls._raise_protocol_error("AES v2 MAC requires 16-byte IV and key")
        b0 = bytearray(16)
        b0[0] = 0x19
        b0[1:14] = iv[1:14]
        b0[14:16] = pack(">H", len(payload))
        cmac = CMAC.new(cls._to_bytes(mac_key), ciphermod=AES)
        cmac.update(cls._to_bytes(b0))
        cmac.update(cls._to_bytes(payload))
        return bytearray(cmac.digest()[:8])

    @classmethod
    def _crypt_payload_and_mac_v2_aes128(
            cls, encryption_key: Octets, iv: Octets, payload: Octets,
            mac: Octets) -> Tuple[bytearray, bytearray]:
        if len(encryption_key) != 16 or len(iv) != 16 or len(mac) != 8:
            cls._raise_protocol_error(
                "AES v2 secure payload has invalid key or IV length")
        stream = AES.new(
            cls._to_bytes(encryption_key), AES.MODE_OFB, iv=cls._to_bytes(iv))
        payload_out = bytearray(stream.encrypt(cls._to_bytes(payload)))
        aligned = cls._ceil_to_multiple(len(payload), 16)
        if aligned > len(payload):
            stream.encrypt(b"\x00" * (aligned - len(payload)))
        mac_out = bytearray(stream.encrypt(cls._to_bytes(mac)))
        return payload_out, mac_out

    @classmethod
    def _build_initial_vector_v2_aes128(
            cls, frame_length: int, code: int, counter_bytes: Octets,
            transaction_id: Octets, challenge_3c: Octets) -> bytearray:
        iv = bytearray(16)
        iv[0] = 0x01
        iv[1] = frame_length & 0xFF
        iv[2] = code
        iv[3:5] = counter_bytes
        iv[5:11] = transaction_id
        iv[11:14] = challenge_3c[1:4]
        return iv

    @classmethod
    def _encrypt_secure_request_v2_aes128(
            cls, command_code: int, transaction_number: int,
            transaction_id: Octets, challenge_3c: Octets,
            encryption_key: Octets, mac_key: Octets,
            payload: Octets) -> bytearray:
        counter_bytes = pack("<H", transaction_number)
        frame_length = 1 + 1 + 2 + len(payload) + 8
        if frame_length > 255:
            cls._raise_protocol_error(
                "secure command payload exceeds maximum frame length")
        iv = cls._build_initial_vector_v2_aes128(
            frame_length, command_code, counter_bytes, transaction_id,
            challenge_3c)
        mac = cls._calculate_mac_v2_aes128(iv, payload, mac_key)
        cipher_payload, cipher_mac = cls._crypt_payload_and_mac_v2_aes128(
            encryption_key, iv, payload, mac)
        return bytearray(counter_bytes) + cipher_payload + cipher_mac

    @classmethod
    def _decrypt_secure_response_v2_aes128(
            cls, response_code: int, transaction_id: Octets,
            challenge_3c: Octets, encryption_key: Octets,
            mac_key: Octets, data: Octets) -> Tuple[int, bytearray]:
        if len(data) < 10:
            cls._raise_protocol_error(
                "secure response too short for AES v2 framing")
        counter_bytes = data[0:2]
        transaction_number = unpack("<H", counter_bytes)[0]
        cipher_payload = data[2:-8]
        cipher_mac = data[-8:]

        frame_length = 2 + len(data)
        if frame_length > 255:
            cls._raise_protocol_error(
                "secure response exceeds maximum frame length")
        iv = cls._build_initial_vector_v2_aes128(
            frame_length, response_code, counter_bytes, transaction_id,
            challenge_3c)
        payload, mac_plain = cls._crypt_payload_and_mac_v2_aes128(
            encryption_key, iv, cipher_payload, cipher_mac)
        expected_mac = cls._calculate_mac_v2_aes128(iv, payload, mac_key)
        if not cls._ct_eq(mac_plain, expected_mac):
            cls._raise_protocol_error(
                "secure response MAC verification failed for AES v2")
        return transaction_number, payload

    def _secure_command_exchange(
            self, command_code: int, command_payload: Octets,
            timeout: float) -> bytearray:
        command_context = self._capture_secure_command_context()
        transaction_number = command_context.transaction_number
        transaction_id = command_context.transaction_id
        credentials = command_context.credentials

        try:
            if isinstance(credentials, DesSecureSessionCredentials):
                secure_payload = bytearray(pack("<H", transaction_number)) \
                    + transaction_id + bytearray(command_payload)
                encrypted_command = self._encrypt_secure_command_des(
                    command_code, secure_payload, credentials.session_key)
            elif isinstance(credentials, Aes128SecureSessionCredentials):
                encrypted_command = self._encrypt_secure_request_v2_aes128(
                    command_code, transaction_number, transaction_id,
                    credentials.challenge_3c, credentials.encryption_key,
                    credentials.mac_key, bytearray(command_payload))
            else:
                self._raise_protocol_error("unknown secure session scheme")

            encrypted_response = self._send_without_response_idm(
                command_code, encrypted_command, timeout)
            response_code = (command_code + 1) & 0xFF

            if isinstance(credentials, DesSecureSessionCredentials):
                rsp_tn, response_payload = self._decrypt_secure_response_des(
                    response_code, transaction_id, credentials.session_key,
                    encrypted_response)
            elif isinstance(credentials, Aes128SecureSessionCredentials):
                rsp_tn, response_payload = \
                    self._decrypt_secure_response_v2_aes128(
                        response_code, transaction_id,
                        credentials.challenge_3c, credentials.encryption_key,
                        credentials.mac_key, encrypted_response)
            else:
                self._raise_protocol_error("unknown secure session scheme")
        finally:
            # This context is a copy of the session made for one command,
            # so its keys are overwritten as soon as the exchange is over.
            command_context.zeroize()

        context = self._ensure_authenticated_context()
        if rsp_tn <= context.transaction_number:
            self._raise_protocol_error(
                "secure response transaction number did not advance")
        context.transaction_number = rsp_tn
        return response_payload

    def secure_transceive(
            self, command_code: int, command_payload: Octets,
            timeout: float) -> bytearray:
        """Encrypt a command, transceive it, and return the response.

        The *command_code* and *command_payload* are encrypted under the
        active secure session, sent to the card, and the decrypted response
        payload is returned. This is the low-level primitive behind the typed
        secure commands (:meth:`read`, :meth:`write`, ...) and is exposed for
        callers that need to drive arbitrary secure commands (for example a
        remote crypto oracle that holds the keys while a separate client owns
        the reader). Requires a prior :meth:`mutual_authentication` (or
        :meth:`mutual_authentication_v2`).

        """
        return self._secure_command_exchange(
            command_code, command_payload, timeout)

    def _is_present(self):
        # Perform a presence check. Modern FeliCa cards implement the
        # RequestResponse command, so we'll try that first. If it
        # fails we resort the generic way that works for all type 3
        # tags (but resets the card operating mode to zero).
        try:
            return self.request_response() in (0, 1, 2, 3)
        except tt3.Type3TagCommandError:
            return super(FelicaStandard, self)._is_present()

    def dump(self):
        # Dump the content of a FeliCa card as good as possible. This
        # is unfortunately rather complex because we want to reflect
        # the area structure with indentation and summarize overlapped
        # services under a single item.

        def print_system(system_code):
            # Print system information
            system_code_map = {
                0x0000: "SDK Sample",
                0x0003: "Suica",
                0x12FC: "NDEF",
                0x811D: "Edy",
                0x8620: "Blackboard",
                0xFE00: "Common Area",
            }
            return ["System {0:04X} ({1})".format(
                system_code, system_code_map.get(system_code, 'unknown'))]

        def print_area(area_from, area_last, depth):
            # Prints area information with indentation.
            return ["{indent}Area {0:04X}--{1:04X}".format(
                area_from, area_last, indent=depth*'  ')]

        def print_service(services, depth):
            # This function processes a list of overlapped services
            # and reads all block data if there is one service that
            # does not require a key. First we figure out the common
            # service type and which access modes are available.
            service_type = access_types = None
            if services[0] >> 2 & 0b1111 == 0b0010:
                service_type = "Random"
                access_types = " & ".join([(
                    "write with key", "write w/o key",
                    "read with key", "read w/o key")[x & 3] for x in services])
            if services[0] >> 2 & 0b1111 == 0b0011:
                service_type = "Cyclic"
                access_types = " & ".join([(
                    "write with key", "write w/o key",
                    "read with key", "read w/o key")[x & 3] for x in services])
            if services[0] >> 2 & 0b1110 == 0b0100:
                service_type = "Purse"
                access_types = " & ".join([(
                    "direct with key", "direct w/o key",
                    "cashback with key", "cashback w/o key",
                    "decrement with key", "decrement w/o key",
                    "read with key", "read w/o key")[x & 7] for x in services])
            if service_type is None:
                # The service attribute table leaves other values
                # undefined, so there is nothing to describe beyond the
                # attribute bits themselves.
                service_type = "Type {0:06b}b".format(services[0] & 0b111111)
                access_types = "unknown access"
            # Now we print one line to verbosely describe the service
            # and list the service codes.
            service_codes = " ".join(["0x{0:04X}".format(x) for x in services])
            lines = [
                "{indent}{type} Service {number}: {access} ({0})".format(
                    service_codes, indent=depth*'  ', type=service_type,
                    number=services[0] >> 6, access=access_types)]
            # The final piece is to see if any of the services allows
            # us to read block data without a key. Services w/o key
            # have the last bit set to 1, so we generate a list of
            # only those services and iterate over the slice from the
            # last item to end (that's one or zero services).
            for service in [sc for sc in services if sc & 1][-1:]:
                sc = tt3.ServiceCode(service >> 6, service & 0b111111)
                for line in self.dump_service(sc):
                    lines.append(depth*'  ' + ' ' + line)
            return lines

        # Unfortunately there are some older cards with reduced
        # command support. If request_system_code() is not supported
        # we can only see if the current system code is NDEF and try
        # to dup that, otherwise it is the end.
        try:
            card_system_codes = self.request_system_code()
        except nfc.tag.TagCommandError:
            if self.sys == 0x12FC:
                return super(FelicaStandard, self).dump()
            else:
                return ["unable to create a memory dump"]

        # A FeliCa card has one or more systems, each system has one
        # or more areas which may be nested, and an area may have zero
        # to many services. The outer loop iterates over all system
        # codes that are present on the card. The inner loop iterates
        # by index over all area and service definitions.
        lines = []
        for system_code in card_system_codes:

            # A system must be activated first, this is what the
            # polling() command does.
            idm, pmm = self.polling(system_code)
            self.idm = idm
            self.pmm = pmm
            self.sys = system_code
            lines.extend(print_system(system_code))

            area_stack = []
            overlap_services = []

            # Walk through the list of services by index. The first
            # index for which there is no service returns None and
            # terminate the loop.
            for service_index in itertools.count():  # pragma: no branch
                assert service_index < 0x10000
                depth = len(area_stack)
                area_or_service = self.search_service_code(service_index)
                if area_or_service is None:
                    # Went beyond the service index. Print overlap
                    # services if any and exit loop.
                    if len(overlap_services) > 0:
                        lines.extend(print_service(overlap_services, depth))
                        overlap_services = []
                    break
                elif len(area_or_service) == 1:
                    # Found a service definition. Add as overlap
                    # service if it is either the first or same type
                    # (Random, Cyclic, Purse) as the previous one. If
                    # it is different then print the current overlap
                    # services and remember this for the next round.
                    service = area_or_service[0]
                    end_overlap_services = False
                    if len(overlap_services) == 0:
                        overlap_services.append(service)
                    elif service >> 4 == overlap_services[-1] >> 4:
                        if service >> 4 & 1:  # purse
                            overlap_services.append(service)
                        elif service >> 2 == overlap_services[-1] >> 2:
                            overlap_services.append(service)
                        else:
                            end_overlap_services = True
                    else:
                        end_overlap_services = True
                    if end_overlap_services:
                        lines.extend(print_service(overlap_services, depth))
                        overlap_services = [service]
                elif len(area_or_service) == 2:
                    # Found an area definition. Print any services
                    # that we might so far have assembled, then
                    # process the area information.
                    if len(overlap_services) > 0:
                        lines.extend(print_service(overlap_services, depth))
                        overlap_services = []
                    area_from, area_last = area_or_service
                    if len(area_stack) > 0 and area_from > area_stack[-1][1]:
                        area_stack.pop()
                    lines.extend(print_area(area_from, area_last, depth))
                    area_stack.append((area_from, area_last))

        return lines

    def request_service(self, service_list):
        """Verify existence of a service (or area) and get the key version.

        Each service (or area) to verify must be given as a
        :class:`~nfc.tag.tt3.ServiceCode` in the iterable
        *service_list*. The key versions are returned as a list of
        16-bit integers, in the order requested. If a specified
        service (or area) does not exist, the key version will be
        0xFFFF.

        0xFFFF is the marker for a node that does not exist, not a
        marker for a service that needs no authentication: a service
        whose attribute requires no key reports a genuine key version
        like any other node.

        Command execution errors raise :exc:`~nfc.tag.TagCommandError`.

        """
        self._validate_list_length(
            "service_list", len(service_list), 1, self.MAX_SERVICE_CODES)
        timeout = self._scaled_timeout(
            self.REQUEST_SERVICE_PMMSLOT, len(service_list))
        pack = lambda x: x.pack()  # noqa: E731
        data = bytearray([len(service_list)]) \
            + b''.join(map(pack, service_list))
        data = self._send_standard_command(
            self.REQUEST_SERVICE_CMD, data, timeout)
        self._validate_exact_length(data, 1 + len(service_list) * 2)
        return [unpack("<H", data[i:i+2])[0] for i in range(1, len(data), 2)]

    def request_response(self):
        """Verify that a card is still present and get its operating mode.

        The Request Response command returns the current operating
        state of the card. The operating state changes with the
        authentication process, a card is in Mode 0 after power-up or
        a Polling command, transitions to Mode 1 with Authentication1,
        to Mode 2 with Authentication2, and Mode 3 with any of the
        card issuance commands. The :meth:`request_response` method
        returns the mode as an integer.

        Command execution errors raise
        :exc:`~nfc.tag.TagCommandError`.

        """
        timeout = self._scaled_timeout(self.REQUEST_RESPONSE_PMMSLOT, 1)
        data = self._send_standard_command(
            self.REQUEST_RESPONSE_CMD, b'', timeout)
        self._validate_exact_length(data, 1)
        return data[0]  # mode

    def search_service_code(self, service_index):
        """Search for a service code that corresponds to an index.

        The Search Service Code command provides access to the
        iterable list of services and areas within the activated
        system. The *service_index* argument may be any value from 0
        to 0xffff. As long as there is a service or area found for a
        given *service_index*, the information returned is a tuple
        with either one or two 16-bit integer elements. Two integers
        are returned for an area definition, the first is the area
        code and the second is the largest possible service index for
        the area. One integer, the service code, is returned for a
        service definition. The return value is :const:`None` if the
        *service_index* was not found.

        For example, to print all services and areas of the active
        system: ::

            for i in xrange(0x10000):
                area_or_service = tag.search_service_code(i)
                if area_or_service is None:
                    break
                elif len(area_or_service) == 1:
                    sc = area_or_service[0]
                    print(nfc.tag.tt3.ServiceCode(sc >> 6, sc & 0x3f))
                elif len(area_or_service) == 2:
                    area_code, area_last = area_or_service
                    print("Area {0:04x}--{0:04x}".format(area_code, area_last))

        Command execution errors raise :exc:`~nfc.tag.TagCommandError`.

        """
        log.debug("search service code index {0}".format(service_index))
        # The maximum response time is given by the value of PMM[3].
        # Some cards (like RC-S860 with IC RC-S915) encode a value
        # that is too short, thus we use at lest 2 ms.
        timeout = self._base_timeout(
            self.SEARCH_SERVICE_CODE_PMMSLOT, enforce_min=True)
        data = pack("<H", service_index)
        data = self._send_standard_command(
            self.SEARCH_SERVICE_CODE_CMD, data, timeout)
        if data != b"\xFF\xFF":
            unpack_format = "<H" if len(data) == 2 else "<HH"
            return unpack(unpack_format, data)

    def request_system_code(self):
        """Return all system codes that are registered in the card.

        A card has one or more system codes that correspond to logical
        partitions (systems). Each system has a system code that could
        be used in a polling command to activate that system. The
        system codes responded by the card are returned as a list of
        16-bit integers. ::

            for system_code in tag.request_system_code():
                print("System {0:04X}".format(system_code))

        Command execution errors raise :exc:`~nfc.tag.TagCommandError`.

        """
        log.debug("request system code list")
        timeout = self._base_timeout(
            self.REQUEST_SYSTEM_CODE_PMMSLOT, enforce_min=True)
        data = self._send_standard_command(
            self.REQUEST_SYSTEM_CODE_CMD, b'', timeout)
        self._validate_exact_length(data, 1 + data[0] * 2)
        return [unpack(">H", data[i:i+2])[0] for i in range(1, len(data), 2)]

    def request_block_information(
            self, node_code_list: Sequence[int]) -> List[int]:
        """Return assigned block counts for node codes.

        The *node_code_list* argument must provide one or more
        16-bit integers. The return value is a list of 16-bit block
        counts in the same order as requested.

        Command execution errors raise :exc:`~nfc.tag.TagCommandError`.

        """
        self._validate_list_length(
            "node_code_list", len(node_code_list), 1, self.MAX_NODE_CODES)
        timeout = self._scaled_timeout(
            self.REQUEST_BLOCK_INFORMATION_PMMSLOT,
            len(node_code_list), enforce_min=True)
        data = bytearray([len(node_code_list)]) \
            + b''.join([pack("<H", x) for x in node_code_list])
        data = self._send_standard_command(
            self.REQUEST_BLOCK_INFORMATION_CMD, data, timeout)
        self._validate_min_length(data, 1)
        self._validate_exact_length(data, 1 + data[0] * 2)
        return [unpack("<H", data[i:i+2])[0] for i in range(1, len(data), 2)]

    def request_block_information_ex(
            self,
            node_code_list: Sequence[int]) -> Tuple[List[int], List[int]]:
        """Return assigned and free block counts for node codes.

        The *node_code_list* argument must provide one or more
        16-bit integers. The return value is a tuple
        ``(assigned_block_counts, free_block_counts)``.

        Command execution errors raise :exc:`~nfc.tag.TagCommandError`.

        """
        self._validate_list_length(
            "node_code_list", len(node_code_list), 1, self.MAX_NODE_CODES)
        timeout = self._scaled_timeout(
            self.REQUEST_BLOCK_INFORMATION_EX_PMMSLOT,
            len(node_code_list), enforce_min=True)
        data = bytearray([len(node_code_list)]) \
            + b''.join([pack("<H", x) for x in node_code_list])
        data = self._send_standard_command(
            self.REQUEST_BLOCK_INFORMATION_EX_CMD, data, timeout)

        self._validate_min_length(data, 2)
        status_flag1, status_flag2 = data[0], data[1]
        if status_flag1 != 0:
            self._raise_status_flag_error(status_flag1, status_flag2)

        self._validate_min_length(data, 3)
        count = data[2]
        self._validate_exact_length(data, 3 + count * 4)

        assigned, free = list(), list()
        for i in range(count):
            offset = 3 + i * 4
            assigned.append(unpack("<H", data[offset:offset+2])[0])
            free.append(unpack("<H", data[offset+2:offset+4])[0])
        return assigned, free

    def request_code_list(
            self, parent_node_code: int,
            index: int) -> Tuple[bool, List[AreaCodeRange], List[int]]:
        """Return area and service codes under a parent node code.

        The return value is a tuple
        ``(continue_flag, area_code_ranges, service_codes)`` where
        *area_code_ranges* is a list of ``(area_code, area_last)``
        tuples and *service_codes* is a list of 16-bit integers.

        Command execution errors raise :exc:`~nfc.tag.TagCommandError`.

        """
        timeout = self._base_timeout(
            self.REQUEST_CODE_LIST_PMMSLOT, enforce_min=True)
        data = pack("<HH", parent_node_code, index)
        data = self._send_standard_command(
            self.REQUEST_CODE_LIST_CMD, data, timeout)

        self._validate_min_length(data, 2)
        status_flag1, status_flag2 = data[0], data[1]
        if status_flag1 != 0:
            self._raise_status_flag_error(status_flag1, status_flag2)

        self._validate_min_length(data, 5)
        continue_flag = bool(data[2])
        area_count = data[3]
        offset = 4
        self._validate_min_length(data, offset + area_count * 4 + 1)

        area_code_ranges = list()
        for i in range(area_count):
            area_data = data[offset+i*4:offset+(i+1)*4]
            area_code_ranges.append(unpack("<HH", area_data))
        offset = offset + area_count * 4

        service_count = data[offset]
        offset = offset + 1
        self._validate_exact_length(data, offset + service_count * 2)

        service_codes = list()
        for i in range(service_count):
            service_codes.append(
                unpack("<H", data[offset+i*2:offset+(i+1)*2])[0])

        return continue_flag, area_code_ranges, service_codes

    def set_parameter(self, encryption_type: int, packet_type: int) -> None:
        """Configure secure messaging parameters.

        Valid values for *encryption_type* are 0 or 1 and valid
        values for *packet_type* are 0 or 1.

        Command execution errors raise :exc:`~nfc.tag.TagCommandError`.

        """
        timeout = self._base_timeout(
            self.SET_PARAMETER_PMMSLOT, enforce_min=True)
        data = bytearray([0, 0, 0, 0, encryption_type, packet_type, 0, 0])
        data = self._send_standard_command(
            self.SET_PARAMETER_CMD, data, timeout)
        self._validate_exact_length(data, 2)
        self._validate_status_flags(data)

    def get_container_issue_information(self) -> Dict[str, bytearray]:
        """Return container issue information.

        The return value is a dictionary with the keys
        ``format_version_carrier_information`` and
        ``mobile_phone_model_information``.

        Command execution errors raise :exc:`~nfc.tag.TagCommandError`.

        """
        timeout = self._base_timeout(
            self.GET_CONTAINER_ISSUE_INFORMATION_PMMSLOT, enforce_min=True)
        data = self._send_standard_command(
            self.GET_CONTAINER_ISSUE_INFORMATION_CMD, b'\x00\x00', timeout)
        self._validate_exact_length(data, 16)
        return {
            "format_version_carrier_information": data[0:5],
            "mobile_phone_model_information": data[5:16]
        }

    def get_container_property(self, property_index: int) -> bytearray:
        """Return raw bytes of the selected container property."""
        timeout = self._base_timeout(
            self.GET_CONTAINER_PROPERTY_PMMSLOT, enforce_min=True)
        data = self.send_cmd_recv_rsp(
            self.GET_CONTAINER_PROPERTY_CMD, pack("<H", property_index),
            timeout, send_idm=False, check_status=False)
        self._validate_min_length(data, 1)
        return data

    def get_container_id(self) -> bytearray:
        """Return the current container IDm as an 8-byte bytearray."""
        timeout = self._base_timeout(
            self.GET_CONTAINER_ID_PMMSLOT, enforce_min=True)
        data = self.send_cmd_recv_rsp(
            self.GET_CONTAINER_ID_CMD, b'\x00\x00', timeout,
            send_idm=False, check_status=False)
        self._validate_exact_length(data, 8)
        return data

    def get_system_status(self) -> Tuple[int, bytearray]:
        """Return system status information.

        The return value is a tuple ``(flag, data)`` where *data* is
        a bytearray.

        Command execution errors raise :exc:`~nfc.tag.TagCommandError`.

        """
        timeout = self._base_timeout(
            self.GET_SYSTEM_STATUS_PMMSLOT, enforce_min=True)
        data = self._send_standard_command(
            self.GET_SYSTEM_STATUS_CMD, b'\x00\x00', timeout)

        self._validate_status_flags(data)
        self._validate_min_length(data, 4)

        flag, data_len = data[2], data[3]
        self._validate_exact_length(data, 4 + data_len)
        return flag, data[4:4+data_len]

    def request_product_information(self) -> bytearray:
        """Return product information bytes.

        Command execution errors raise :exc:`~nfc.tag.TagCommandError`.

        """
        timeout = self._base_timeout(
            self.REQUEST_PRODUCT_INFORMATION_PMMSLOT, enforce_min=True)
        data = self._send_standard_command(
            self.REQUEST_PRODUCT_INFORMATION_CMD, b'', timeout)

        self._validate_status_flags(data)
        self._validate_min_length(data, 3)

        data_len = data[2]
        self._validate_exact_length(data, 3 + data_len)
        return data[3:3+data_len]

    def request_specification_version(self) -> Optional[SpecificationVersion]:
        """Return specification version information.

        The return value is either :const:`None` or a
        :class:`SpecificationVersion` with ``format_version``,
        ``basic_version`` and ``option_versions``. The individual option
        versions can also be accessed by name, e.g.
        :attr:`~SpecificationVersion.random_id_option_version`.

        Command execution errors raise :exc:`~nfc.tag.TagCommandError`.

        """
        timeout = self._base_timeout(
            self.REQUEST_SPECIFICATION_VERSION_PMMSLOT, enforce_min=True)
        data = self._send_standard_command(
            self.REQUEST_SPECIFICATION_VERSION_CMD, b'\x00\x00', timeout)

        self._validate_min_length(data, 2)
        status_flag1, status_flag2 = data[0], data[1]
        if status_flag1 != 0:
            self._raise_status_flag_error(status_flag1, status_flag2)
        if len(data) == 2:
            return None

        version_data = data[2:]
        self._validate_min_length(version_data, 4)
        if version_data[0] != 0x00:
            self._raise_protocol_error(
                "specification version format version must be 0x00")
        option_count = version_data[3]
        self._validate_exact_length(version_data, 4 + option_count * 2)

        option_versions = list()
        for i in range(option_count):
            offset = 4 + i * 2
            option_versions.append(
                self._parse_option_version(version_data[offset:offset+2]))

        return SpecificationVersion(
            format_version=version_data[0],
            basic_version=self._parse_option_version(version_data[1:3]),
            option_versions=option_versions,
        )

    def reset_mode(self) -> None:
        """Reset the operating mode of the card.

        Command execution errors raise :exc:`~nfc.tag.TagCommandError`.

        """
        timeout = self._base_timeout(
            self.RESET_MODE_PMMSLOT, enforce_min=True)
        data = self._send_standard_command(
            self.RESET_MODE_CMD, b'\x00\x00', timeout)
        self._validate_exact_length(data, 2)
        self._validate_status_flags(data)

    def get_area_information(self, node_code: int) -> Tuple[int, bytearray]:
        """Return information of an area node code.

        The return value is a tuple ``(node_code, data)`` where
        *data* is a two-byte bytearray.

        Command execution errors raise :exc:`~nfc.tag.TagCommandError`.

        """
        timeout = self._base_timeout(
            self.GET_AREA_INFORMATION_PMMSLOT, enforce_min=True)
        data = self._send_standard_command(
            self.GET_AREA_INFORMATION_CMD, pack("<H", node_code), timeout)

        self._validate_min_length(data, 2)
        status_flag1, status_flag2 = data[0], data[1]
        if status_flag1 != 0:
            self._raise_status_flag_error(status_flag1, status_flag2)

        self._validate_exact_length(data, 6)
        area_node_code = unpack("<H", data[2:4])[0]
        return area_node_code, data[4:6]

    def get_node_property(
            self, node_property_type: int,
            node_code_list: Sequence[int]) -> List[NodeProperty]:
        """Return properties for a list of node codes.

        If *node_property_type* is 0x00 (value-limited purse service),
        each list entry is a dictionary with
        ``enabled``, ``upper_limit``, ``lower_limit``, and
        ``generation_number``.
        If *node_property_type* is 0x01 (MAC communication), each list
        entry is a dictionary with only ``enabled``.

        Command execution errors raise :exc:`~nfc.tag.TagCommandError`.

        """
        self._validate_list_length(
            "node_code_list", len(node_code_list), 1,
            self.MAX_NODE_PROPERTY_CODES)
        timeout = self._scaled_timeout(
            self.GET_NODE_PROPERTY_PMMSLOT,
            max(1, min(len(node_code_list), 16)), enforce_min=True)
        data = bytearray([node_property_type, len(node_code_list)]) \
            + b''.join([pack("<H", x) for x in node_code_list])
        data = self._send_standard_command(
            self.GET_NODE_PROPERTY_CMD, data, timeout)

        self._validate_status_flags(data)
        self._validate_min_length(data, 3)

        node_count = data[2]
        if node_count != len(node_code_list):
            self._raise_data_size_error()

        if (node_property_type
                == self.NODE_PROPERTY_VALUE_LIMITED_PURSE_SERVICE):
            self._validate_exact_length(data, 3 + node_count * 10)
            properties = list()
            for i in range(node_count):
                offset = 3 + i * 10
                properties.append({
                    "enabled": data[offset] == 0x01,
                    "upper_limit": unpack("<i", data[offset+1:offset+5])[0],
                    "lower_limit": unpack("<i", data[offset+5:offset+9])[0],
                    "generation_number": data[offset+9]
                })
            return properties

        if node_property_type == self.NODE_PROPERTY_MAC_COMMUNICATION:
            self._validate_exact_length(data, 3 + node_count)
            return [{"enabled": x == 0x01} for x in data[3:]]

        if len(data) == 3 + node_count * 10:
            properties = list()
            for i in range(node_count):
                offset = 3 + i * 10
                properties.append({
                    "enabled": data[offset] == 0x01,
                    "upper_limit": unpack("<i", data[offset+1:offset+5])[0],
                    "lower_limit": unpack("<i", data[offset+5:offset+9])[0],
                    "generation_number": data[offset+9]
                })
            return properties

        if len(data) == 3 + node_count:
            return [{"enabled": x == 0x01} for x in data[3:]]

        self._raise_data_size_error()

    def request_service_v2(
            self, service_list: Sequence[tt3.ServiceCode]
            ) -> Tuple[int, List[ServiceVersion]]:
        """Return service key version information (FeliCa Standard v2).

        The return value is a tuple ``(crypto_id, key_versions)``.
        If *crypto_id* is 0x41 or 0x43, key version entries are
        ``(aes_key_version, des_key_version)`` tuples. Otherwise each
        key version entry is a single 16-bit integer.

        Command execution errors raise :exc:`~nfc.tag.TagCommandError`.

        """
        self._validate_list_length(
            "service_list", len(service_list), 1, self.MAX_SERVICE_CODES)
        timeout = self._scaled_timeout(
            self.REQUEST_SERVICE_V2_PMMSLOT,
            len(service_list), enforce_min=True)
        pack_service = lambda x: x.pack()  # noqa: E731
        data = bytearray([len(service_list)]) \
            + b''.join(map(pack_service, service_list))
        data = self._send_standard_command(
            self.REQUEST_SERVICE_V2_CMD, data, timeout)

        self._validate_status_flags(data)
        self._validate_min_length(data, 4)

        crypto_id, node_count = data[2], data[3]
        payload = data[4:]
        if node_count != len(service_list):
            self._raise_data_size_error()

        if crypto_id in (
                self.REQUEST_SERVICE_V2_DUAL_KEYS_AES128,
                self.REQUEST_SERVICE_V2_DUAL_KEYS_AES_CMAC):
            self._validate_exact_length(payload, node_count * 4)
            key_versions = list()
            for i in range(node_count):
                aes_offset = i * 2
                des_offset = node_count * 2 + aes_offset
                aes_version = unpack("<H", payload[aes_offset:aes_offset+2])[0]
                des_version = unpack("<H", payload[des_offset:des_offset+2])[0]
                key_versions.append((aes_version, des_version))
        else:
            self._validate_exact_length(payload, node_count * 2)
            key_versions = list()
            for i in range(node_count):
                offset = i * 2
                key_versions.append(unpack("<H", payload[offset:offset+2])[0])

        return crypto_id, key_versions

    @staticmethod
    def generate_service_keys_des(
            system_key: Octets, area_keys: Sequence[Octets],
            service_keys: Sequence[Octets]) -> Tuple[bytearray, bytearray]:
        """Generate group and user service keys from key hierarchies."""
        current_key = bytearray(system_key)
        for key in area_keys:
            current_key = FelicaStandard._encrypt_des_block(current_key, key)
        group_service_key = current_key
        for key in service_keys:
            current_key = FelicaStandard._encrypt_des_block(current_key, key)
        user_service_key = current_key
        return group_service_key, user_service_key

    @staticmethod
    def generate_group_key_v2_aes128(node_keys: Sequence[Octets]) -> bytearray:
        """Generate a FeliCa Standard v2 (AES-128) group key.

        The *node_keys* argument is an ordered sequence of 16-byte node
        (service) keys. Starting from a fixed initial chaining block, each
        node key is folded in as an AES-128 key. The 16-byte group key is
        returned.

        """
        current_key = bytearray(FelicaStandard.V2_AES128_NODE_KEY_INIT)
        for key in node_keys:
            current_key = FelicaStandard._encrypt_aes128_block(
                current_key, key)
        return current_key

    def authenticated_context(self) -> Optional[AuthenticatedContext]:
        """Return current secure session context or :const:`None`."""
        if self._authenticated_context is None:
            return None
        return self._clone_authenticated_context(self._authenticated_context)

    def set_authenticated_context(
            self, context: AuthenticatedContext) -> None:
        """Set secure session context.

        The *context* argument must be an :class:`AuthenticatedContext`
        instance.

        """
        self._authenticated_context = \
            self._normalize_authenticated_context(context)

    def clear_authenticated_context(self) -> None:
        """Clear secure session context.

        The session keys are overwritten in place before the context is
        dropped, so that they do not linger in a buffer that is only
        waiting to be garbage collected.

        """
        if self._authenticated_context is not None:
            self._authenticated_context.zeroize()
        self._authenticated_context = None

    def authenticated_scheme(self) -> Optional[SecureSessionScheme]:
        """Return current secure session scheme or :const:`None`."""
        if self._authenticated_context is None:
            return None
        return self._authenticated_context.scheme

    def authentication1(
            self, areas: Sequence[int], services: Sequence[tt3.ServiceCode],
            challenge_1a: Octets) -> Tuple[bytearray, bytearray]:
        """Perform FeliCa Standard Authentication1 command.

        The *areas* argument is a list of 16-bit area codes.
        The *services* argument is a list of
        :class:`~nfc.tag.tt3.ServiceCode` objects.
        The *challenge_1a* argument must be 8 bytes.

        The service code list is not restricted to services. It may
        equally name an area or the system node 0xFFFF, and the card
        folds that node's key into the derivation chain; both count as
        authentication-required nodes, which the card requires to come
        before any authentication-free service in the list.

        Returns a tuple ``(challenge_1b, challenge_2a)``.

        """
        if len(challenge_1a) != 8:
            raise ValueError("challenge_1a must be 8 bytes")
        if len(areas) > self.MAX_SERVICE_CODES:
            raise ValueError("too many areas for authentication1")
        if len(services) > self.MAX_SERVICE_CODES:
            raise ValueError("too many services for authentication1")
        timeout = self._scaled_timeout(
            self.AUTHENTICATION1_PMMSLOT, len(areas) + len(services),
            enforce_min=True)
        service_codes = [int(service) for service in services]
        data = bytearray([len(areas)]) \
            + b''.join([pack("<H", area) for area in areas]) \
            + bytearray([len(service_codes)]) \
            + b''.join([pack("<H", code) for code in service_codes]) \
            + bytearray(challenge_1a)
        data = self._send_standard_command(
            self.AUTHENTICATION1_CMD, data, timeout)
        self._validate_exact_length(data, 16)
        return data[0:8], data[8:16]

    def authentication2(self, challenge_2b: Octets) -> bytearray:
        """Perform FeliCa Standard Authentication2 command.

        The *challenge_2b* argument must be 8 bytes.
        Returns encrypted response payload bytes.

        """
        if len(challenge_2b) != 8:
            raise ValueError("challenge_2b must be 8 bytes")
        timeout = self._base_timeout(
            self.AUTHENTICATION2_PMMSLOT, enforce_min=True)
        data = self._send_command_with_idm_no_idm_response(
            self.AUTHENTICATION2_CMD, bytearray(challenge_2b), timeout)
        self._validate_min_length(data, 8)
        return data

    def _decrypt_authentication2_payload_des(
            self, encrypted_payload: Octets, session_key: Octets) -> bytearray:
        plain = self._decrypt_des_cbc_zero_iv(encrypted_payload, session_key)
        if self._check_packet_mac_des(
                plain, self.AUTHENTICATION2_CMD + 1) is False:
            self._raise_protocol_error(
                "authentication2 response MAC verification failed")
        if len(plain) < 8:
            self._raise_protocol_error(
                "authentication2 response payload too short")
        return plain[:-8]

    def mutual_authentication(
            self, areas: Sequence[int], services: Sequence[tt3.ServiceCode],
            group_service_key: Octets,
            user_service_key: Octets) -> Tuple[bytearray, bytearray]:
        """Perform DES mutual authentication and open a secure session.

        Returns a tuple ``(issue_id, issue_parameter)``.

        """
        if len(areas) == 0 and len(services) == 0:
            raise ValueError(
                "mutual authentication requires at least one area or service")
        if len(group_service_key) != 8 or len(user_service_key) != 8:
            raise ValueError("service keys must be 8 bytes")

        random_1 = bytearray(os.urandom(8))
        key_l = self._xor_bytes(group_service_key, self.idm[0:8])
        alpha = self._encrypt_des_block(user_service_key, key_l)
        beta = self._encrypt_des_block(key_l, alpha)

        challenge_1a = self._encrypt_3des_block(random_1, alpha, key_l)
        challenge_1b, challenge_2a = self.authentication1(
            areas, services, challenge_1a)

        if not self._ct_eq(
                self._encrypt_3des_block(random_1, key_l, beta), challenge_1b):
            self._raise_authentication_error(
                "Authentication1 verification failed")

        random_2 = self._decrypt_3des_block(challenge_2a, key_l, beta)
        challenge_2b = self._encrypt_3des_block(random_2, alpha, key_l)
        encrypted_payload = self.authentication2(challenge_2b)
        payload = self._decrypt_authentication2_payload_des(
            encrypted_payload, random_2)
        if len(payload) < 24:
            self._raise_protocol_error(
                "Authentication2 response payload too short")

        transaction_number = unpack("<H", payload[0:2])[0]
        transaction_id = payload[2:8]
        expected_transaction_id = random_1[2:8]
        if transaction_id != expected_transaction_id:
            self._raise_authentication_error(
                "Authentication2 transaction ID mismatch")

        issue_id = payload[8:16]
        issue_parameter = payload[16:24]
        self._authenticated_context = AuthenticatedContext(
            transaction_number=transaction_number,
            transaction_id=transaction_id,
            credentials=DesSecureSessionCredentials(random_2),
            # A block list element's service list index counts the service
            # list only; the area list scopes the key chain and is not
            # addressable. A node whose key is to be changed therefore has
            # to be named among the services, which the system node 0xFFFF
            # may be.
            nodes=[int(service) for service in services],
        )
        # The session key now lives in the context, which clears it when the
        # session ends. These are the copies this exchange made.
        zeroize(random_1, random_2, challenge_1a, challenge_2b, payload,
                key_l, alpha, beta)
        return issue_id, issue_parameter

    @staticmethod
    def _pack_block_list(block_list: Sequence[tt3.BlockCode]) -> bytes:
        return b''.join([block.pack() for block in block_list])

    def _build_block_command_payload(
            self, block_list: Sequence[tt3.BlockCode],
            block_data: Optional[Octets] = None) -> bytearray:
        payload = bytearray([len(block_list)])
        payload.extend(self._pack_block_list(block_list))
        if block_data is not None:
            payload.extend(bytearray(block_data))
        return payload

    def _parse_secure_read_result(
            self, data: Octets, expected_blocks: int) -> List[bytearray]:
        self._validate_status_flags(data, min_length=2)
        self._validate_min_length(data, 3)
        block_count = data[2]
        expected_length = 3 + block_count * 16
        self._validate_min_length(data, expected_length)
        if block_count != expected_blocks:
            self._raise_data_size_error()
        return [
            bytearray(data[3+i*16:3+(i+1)*16])
            for i in range(block_count)
        ]

    def _secure_read(
            self, command_code: int,
            block_list: Sequence[tt3.BlockCode]) -> List[bytearray]:
        # Like Read Without Encryption, a secure read is bounded by its
        # response rather than its command; the DES scheme's padding costs
        # it one block against Read v2.
        maximum = (self.MAX_SECURE_READ_V2_BLOCK_COUNT
                   if command_code == self.READ_V2_CMD
                   else self.MAX_SECURE_READ_BLOCK_COUNT)
        self._validate_list_length("block_list", len(block_list), 1, maximum)
        timeout = self._scaled_timeout(
            self.READ_PMMSLOT, len(block_list), enforce_min=True)
        payload = self._build_block_command_payload(block_list)
        data = self._secure_command_exchange(command_code, payload, timeout)
        return self._parse_secure_read_result(data, len(block_list))

    def read(self, block_list: Sequence[tt3.BlockCode]) -> List[bytearray]:
        """Read data blocks with secure messaging."""
        return self._secure_read(self.READ_CMD, block_list)

    def read_v2(self, block_list: Sequence[tt3.BlockCode]) -> List[bytearray]:
        """Read data blocks with secure messaging v2."""
        return self._secure_read(self.READ_V2_CMD, block_list)

    def _secure_write(
            self, command_code: int, block_list: Sequence[tt3.BlockCode],
            data: Octets) -> None:
        # A write's true ceiling depends on whether its block list elements
        # are two or three byte wide, so there is no single count to check
        # here; the 255 byte packet limit is enforced exactly when the frame
        # is built.
        self._validate_list_length(
            "block_list", len(block_list), 1, self.MAX_BLOCK_COUNT)
        if len(data) != len(block_list) * 16:
            raise ValueError("data length must be 16 * len(block_list)")
        timeout = self._scaled_timeout(
            self.WRITE_PMMSLOT, len(block_list), enforce_min=True)
        payload = self._build_block_command_payload(block_list, data)
        rsp = self._secure_command_exchange(command_code, payload, timeout)
        # A DES secure response is CBC encrypted and therefore padded to a
        # multiple of 8 byte, so only the leading status flags are fixed.
        self._validate_min_length(rsp, 2)
        self._validate_status_flags(rsp)

    def write(self, block_list: Sequence[tt3.BlockCode], data: Octets) -> None:
        """Write data blocks with secure messaging."""
        self._secure_write(self.WRITE_CMD, block_list, data)

    def write_v2(
            self, block_list: Sequence[tt3.BlockCode], data: Octets) -> None:
        """Write data blocks with secure messaging v2."""
        self._secure_write(self.WRITE_V2_CMD, block_list, data)

    def change_keys(self, change_key_params: Sequence[ChangeKeyParam]) -> None:
        """Change node keys through secure Write command.

        Each entry in *change_key_params* must provide the ``node`` whose
        key is replaced, the keys ``parent_key``, ``new_key``, ``old_key``,
        and the ``new_key_version``.

        A block list element names its target by position in the node list
        the session was authenticated against, so a key can only be changed
        for a node that list contains. Resolving the position here, rather
        than assuming one, is what keeps a mistyped node from silently
        rewriting a different node's key. The system node ``0xFFFF`` is
        addressable like any other node when it was named among the
        services of :meth:`mutual_authentication`.

        """
        if len(change_key_params) == 0:
            raise ValueError("change_keys requires at least one entry")
        for params in change_key_params:
            if any(len(params[name]) != 8 for name in (
                    "parent_key", "new_key", "old_key")):
                raise ValueError("all key values must be 8 bytes")

        context = self._ensure_authenticated_context()
        block_list = list()
        payload = bytearray()
        for params in change_key_params:
            node = params["node"]
            parent_key = params["parent_key"]
            new_key = params["new_key"]
            old_key = params["old_key"]
            new_key_version = params["new_key_version"]

            index = context.node_index(node)
            if index is None:
                raise ValueError(
                    "node {0:#06x} is not in the authenticated node list {1}"
                    .format(node, ["{0:#06x}".format(listed)
                                   for listed in context.nodes]))
            if index > 0x0F:
                # The service list index of a block list element is four
                # bits wide.
                raise ValueError(
                    "node {0:#06x} is at position {1} of the authenticated "
                    "node list, which a block list element cannot address"
                    .format(node, index))

            version_block = bytearray(8)
            version_block[6:8] = pack("<H", new_key_version)

            parameter1 = self._encrypt_des_block(version_block, new_key)
            parameter1 = self._encrypt_des_block(parameter1, old_key)
            parameter1 = self._encrypt_des_block(parameter1, parent_key)

            parameter2 = self._encrypt_des_block(new_key, old_key)
            parameter2 = self._encrypt_des_block(parameter2, parent_key)

            payload.extend(parameter1)
            payload.extend(parameter2)
            block_list.append(
                tt3.BlockCode(new_key_version, access=4, service=index))

        self.write(block_list, payload)

    def authentication1_v2(
            self, operation_parameter: int, nodes: Sequence[int],
            challenge_1a: Octets) -> Tuple[bytearray, bytearray, bytearray]:
        """Perform FeliCa Standard v2 Authentication1 command.

        Returns a tuple ``(challenge_1b, challenge_2a, challenge_3c)``.

        """
        if len(challenge_1a) != 16:
            raise ValueError("challenge_1a must be 16 bytes")
        if len(nodes) > self.MAX_SERVICE_CODES:
            raise ValueError("too many nodes for authentication1 v2")
        timeout = self._scaled_timeout(
            self.AUTHENTICATION1_PMMSLOT, len(nodes), enforce_min=True)
        payload = bytearray([operation_parameter, len(nodes)]) \
            + b''.join([pack("<H", node) for node in nodes]) \
            + bytearray(challenge_1a)
        data = self._send_standard_command(
            self.AUTHENTICATION1_V2_CMD, payload, timeout)
        self._validate_exact_length(data, 36)
        return data[0:16], data[16:32], data[32:36]

    def authentication2_v2(self, challenge_2b: Octets) -> bytearray:
        """Perform FeliCa Standard v2 Authentication2 command.

        Returns encrypted response payload bytes.

        """
        if len(challenge_2b) != 16:
            raise ValueError("challenge_2b must be 16 bytes")
        timeout = self._base_timeout(
            self.AUTHENTICATION2_PMMSLOT, enforce_min=True)
        data = self._send_command_with_idm_no_idm_response(
            self.AUTHENTICATION2_V2_CMD, bytearray(challenge_2b), timeout)
        self._validate_min_length(data, 10)
        return data

    def _build_authentication_context_block_v2(
            self, prefix: Sequence[int], idm: Octets) -> bytearray:
        block = bytearray(16)
        block[0:2] = bytearray(prefix)
        block[6:14] = bytearray(idm)
        block[14:16] = self.V2_AES128_AUTH_CONTEXT_SUFFIX
        return block

    def mutual_authentication_v2(
            self, operation_parameter: int, nodes: Sequence[int],
            group_key: Octets, individual_key: Octets
            ) -> Tuple[bytearray, bytearray]:
        """Perform AES-128 mutual authentication and open a v2 session.

        Returns a tuple ``(issue_id, issue_parameter)``.

        """
        if len(nodes) == 0:
            raise ValueError(
                "mutual authentication v2 requires at least one node code")
        if len(group_key) != 16 or len(individual_key) != 16:
            raise ValueError("group_key and individual_key must be 16 bytes")

        random_1 = bytearray(os.urandom(16))
        h = self._xor_bytes(group_key, individual_key)
        alpha = self._encrypt_aes128_block(
            self._build_authentication_context_block_v2(
                [0x01, 0x02], self.idm[0:8]), h)
        beta = self._encrypt_aes128_block(
            self._build_authentication_context_block_v2(
                [0x02, 0x02], self.idm[0:8]), h)

        challenge_1a = self._encrypt_aes128_block(random_1, alpha)
        challenge_1b, challenge_2a, challenge_3c = self.authentication1_v2(
            operation_parameter, nodes, challenge_1a)

        beta_mask = bytearray(16)
        beta_mask[0:4] = challenge_3c
        beta_with_3c = self._xor_bytes(beta, beta_mask)
        if not self._ct_eq(
                self._encrypt_aes128_block(random_1, beta_with_3c),
                challenge_1b):
            self._raise_authentication_error(
                "Authentication1 v2 verification failed")

        random_2 = self._decrypt_aes128_block(challenge_2a, beta_with_3c)
        challenge_2b = self._encrypt_aes128_block(random_2, alpha)
        encrypted_payload = self.authentication2_v2(challenge_2b)
        transaction_id = random_1[2:8]
        encryption_key = self._encrypt_aes128_block(
            self.V2_AES128_DERIVE_ENCRYPTION_KEY_INPUT, random_2)
        mac_key = self._encrypt_aes128_block(
            self.V2_AES128_DERIVE_MAC_KEY_INPUT, random_2)
        transaction_number, payload = self._decrypt_secure_response_v2_aes128(
            self.AUTHENTICATION2_V2_CMD + 1, transaction_id, challenge_3c,
            encryption_key, mac_key, encrypted_payload)
        if len(payload) < 16:
            self._raise_protocol_error(
                "Authentication2 v2 response payload too short")

        issue_id = payload[0:8]
        issue_parameter = payload[8:16]
        self._authenticated_context = AuthenticatedContext(
            transaction_number=transaction_number,
            transaction_id=transaction_id,
            credentials=Aes128SecureSessionCredentials(
                encryption_key=encryption_key,
                mac_key=mac_key,
                challenge_3c=challenge_3c,
            ),
            nodes=[int(node) for node in nodes],
        )
        # The derived session keys now live in the context, which clears
        # them when the session ends. These are the copies this exchange
        # made.
        zeroize(random_1, random_2, challenge_1a, challenge_2b, payload,
                encryption_key, mac_key, h, alpha, beta, beta_with_3c)
        return issue_id, issue_parameter

    def _generate_registration_package_des(
            self, package_plain: Octets, package_key: Octets) -> bytearray:
        if len(package_plain) == 0 or len(package_plain) % 8 != 0:
            raise ValueError(
                "registration package must be multiple of 8 bytes")
        if len(package_key) != 8:
            raise ValueError("package_key must be 8 bytes")

        mac_key = bytearray([x ^ 0xFF for x in bytearray(package_key)])
        encrypted_plain = self._encrypt_des_cbc_zero_iv(package_plain, mac_key)
        if len(encrypted_plain) < 8:
            self._raise_protocol_error(
                "registration package MAC calculation failed")
        mac = encrypted_plain[-8:]
        return self._encrypt_des_cbc_zero_iv(
            bytearray(package_plain) + mac, package_key)

    def register_issue_id(
            self, system_code: int, area0_key_version: int, area0_key: Octets,
            issue_id: Octets, issue_parameter: Octets, package_key: Octets
            ) -> int:
        """Run Register Issue ID secure command.

        Returns remaining block count.

        """
        if (len(area0_key) != 8 or len(issue_id) != 8
                or len(issue_parameter) != 8):
            raise ValueError(
                "area0_key, issue_id and issue_parameter must be 8 bytes")
        package_plain = bytearray(pack(">H", system_code)) \
            + bytearray(pack("<H", area0_key_version)) \
            + bytearray(area0_key) + bytearray(4)
        package = self._generate_registration_package_des(
            package_plain, package_key)

        timeout = self._base_timeout(
            self.REGISTRATION_PMMSLOT, enforce_min=True)
        payload = bytearray(issue_id) + bytearray(issue_parameter) + package
        data = self._secure_command_exchange(
            self.REGISTER_ISSUE_ID_CMD, payload, timeout)
        self._validate_status_flags(data)
        return unpack("<H", data[2:4])[0]

    def register_area(
            self, area_code: int, service_code_range: Tuple[int, int],
            size: int, key_version: int, area_key: Octets,
            package_key: Octets) -> None:
        """Run Register Area secure command."""
        service_begin, service_end = service_code_range
        if area_code != service_begin:
            raise ValueError("area_code must match service_code_range start")
        if len(area_key) != 8:
            raise ValueError("area_key must be 8 bytes")

        package_plain = bytearray(pack(
            "<HHHH", service_begin, service_end, size, key_version))
        package_plain.extend(bytearray(area_key))
        package = self._generate_registration_package_des(
            package_plain, package_key)

        timeout = self._base_timeout(
            self.REGISTRATION_PMMSLOT, enforce_min=True)
        payload = bytearray(pack("<H", area_code)) + package
        data = self._secure_command_exchange(
            self.REGISTER_AREA_CMD, payload, timeout)
        self._validate_status_flags(data)

    def register_service(
            self, service_code: int, size: int, key_version: int,
            service_key: Octets, package_key: Octets) -> int:
        """Run Register Service secure command.

        Returns remaining block count.

        """
        if len(service_key) != 8:
            raise ValueError("service_key must be 8 bytes")

        package_plain = bytearray(pack("<H", service_code))
        package_plain.extend(bytearray(2))
        package_plain.extend(bytearray(pack("<H", size)))
        package_plain.extend(bytearray(pack("<H", key_version)))
        package_plain.extend(bytearray(service_key))
        package = self._generate_registration_package_des(
            package_plain, package_key)

        timeout = self._base_timeout(
            self.REGISTRATION_PMMSLOT, enforce_min=True)
        payload = bytearray(pack("<H", service_code)) + package
        data = self._secure_command_exchange(
            self.REGISTER_SERVICE_CMD, payload, timeout)
        self._validate_status_flags(data)
        return unpack("<H", data[2:4])[0]

    def change_system_block(self) -> None:
        """Run Change System Block secure command."""
        timeout = self._base_timeout(
            self.REGISTRATION_PMMSLOT, enforce_min=True)
        data = self._secure_command_exchange(
            self.CHANGE_SYSTEM_BLOCK_CMD, b'', timeout)
        self._validate_status_flags(data)


class FelicaMobile(FelicaStandard):
    """Mobile FeliCa is a modification of FeliCa for use in mobile
    phones. This class does currently not implement anything specific
    beyond recognition of the Mobile FeliCa OS version.

    """
    IC_CODE_MAP = {
        # IC   IC-NAME    NBR NBW
        0x06: ("1.0",       1,  1),
        0x07: ("1.0",       1,  1),
        0x10: ("2.0",       1,  1),
        0x11: ("2.0",       1,  1),
        0x12: ("2.0",       1,  1),
        0x13: ("2.0",       1,  1),
        0x14: ("3.0",       1,  1),
        0x15: ("3.0",       1,  1),
        0x16: ("3.0",       1,  1),
        0x17: ("3.0",       1,  1),
        0x18: ("3.0",       1,  1),
        0x19: ("3.0",       1,  1),
        0x1A: ("3.0",       1,  1),
        0x1B: ("3.0",       1,  1),
        0x1C: ("3.0",       1,  1),
        0x1D: ("3.0",       1,  1),
        0x1E: ("3.0",       1,  1),
        0x1F: ("3.0",       1,  1),
    }

    def __init__(self, clf, target):
        super(FelicaMobile, self).__init__(clf, target)
        self._product = "FeliCa Mobile " + self.IC_CODE_MAP[self.pmm[1]][0]


class FelicaLite(tt3.Type3Tag):
    """FeliCa Lite is a version of FeliCa with simplified file system and
    security functions. The usable memory is 13 blocks (one block has
    16 byte) plus a one block subtraction register. The tag can be
    configured with a card key to authenticate the tag and protect
    integrity of data reads.

    """
    IC_CODE_MAP = {
        0xF0: "FeliCa Lite (RC-S965)",
    }

    class NDEF(tt3.Type3Tag.NDEF):
        def _read_attribute_data(self):
            log.debug("FelicaLite.read_attribute_data")
            attributes = super(FelicaLite.NDEF, self)._read_attribute_data()
            if attributes is not None and self._tag.is_authenticated:
                # when authenticated we need to make room for the mac
                self._original_nbr = attributes['nbr']
                attributes['nbr'] = min(attributes['nbr'], 3)
            return attributes

        def _write_attribute_data(self, attributes):
            log.debug("FelicaLite.read_attribute_data")
            if self._tag.is_authenticated:
                attributes = attributes.copy()
                attributes['nbr'] = self._original_nbr
            super(FelicaLite.NDEF, self)._write_attribute_data(attributes)

    def __init__(self, clf, target):
        super(FelicaLite, self).__init__(clf, target)
        self._product = self.IC_CODE_MAP[self.pmm[1]]
        self._sk = self._iv = None
        self.read_from_ndef_service = self.read_without_mac
        self.write_to_ndef_service = self.write_without_mac

    def dump(self):
        def oprint(octets):
            return ' '.join(['%02x' % x for x in octets])

        def cprint(octets):
            return ''.join([chr(x) if 32 <= x <= 126 else '.' for x in octets])

        userblocks = list()
        for i in range(0, 14):
            try:
                data = self.read_without_mac(i)
            except tt3.Type3TagCommandError:
                userblocks.append("{0} |{1}|".format(
                    " ".join(16 * ["??"]), 16*"."))
            else:
                userblocks.append("{0} |{1}|".format(
                    oprint(data), cprint(data)))

        lines = list()
        last_block = None
        same_blocks = 0

        for i, block in enumerate(userblocks):
            if block == last_block:
                same_blocks += 1
                continue
            if same_blocks:
                if same_blocks > 1:
                    lines.append("  *  " + last_block)
                same_blocks = 0
            lines.append("{0:3}: ".format(i) + block)
            last_block = block

        if same_blocks:
            if same_blocks > 1:
                lines.append("  *  " + last_block)
            lines.append("{0:3}: ".format(i) + block)

        data = self.read_without_mac(14)
        lines.append(" 14: {0} ({1})".format(oprint(data), "REGA[4]B[4]C[8]"))

        text = ("RC1[8], RC2[8]", "MAC[8]", "IDD[8], DFC[2]",
                "IDM[8], PMM[8]", "SERVICE_CODE[2]",
                "SYSTEM_CODE[2]", "CKV[2]", "CK1[8], CK2[8]",
                "MEMORY_CONFIG")
        config = dict(zip(range(0x80, 0x80+len(text)), text))

        for i in sorted(config.keys()):
            try:
                data = self.read_without_mac(i)
            except tt3.Type3TagCommandError:
                lines.append("{0:3}: {1}({2})".format(
                    i, 16 * "?? ", config[i]))
            else:
                lines.append("{0:3}: {1} ({2})".format(
                    i, oprint(data), config[i]))

        return lines

    @staticmethod
    def generate_mac(data, key, iv, flip_key=False):
        # Data is first split into tuples of 8 character bytes, each
        # tuple then reversed and joined, finally all joined back to
        # one string that is then 3DES encrypted with key and
        # initialization vector iv. If flip_key is True then the key
        # halfs will be exchanged (this is used to generate a mac for
        # write). The resulting mac is the last 8 bytes returned in
        # reversed order.
        assert len(data) % 8 == 0 and len(key) == 16 and len(iv) == 8
        key = bytes(key[8:] + key[:8]) if flip_key else bytes(key)
        txt = b''.join([
            struct.pack("{}B".format(len(x)), *reversed(x))
            if isinstance(x[0], int)
            else b''.join(reversed(x))
            for x in zip(*[iter(bytes(data))]*8)])
        mac = FelicaStandard._encrypt_3des_cbc(txt, key, iv)
        return bytearray(mac[-8:][::-1])

    def protect(self, password=None, read_protect=False, protect_from=0):
        """Protect a FeliCa Lite Tag.

        A FeliCa Lite Tag can be provisioned with a custom password
        (or the default manufacturer key if the password is an empty
        string or bytearray) to ensure that data retrieved by future
        read operations, after authentication, is genuine. Read
        protection is not supported.

        A non-empty *password* must provide at least 128 bit key
        material, in other words it must be a string or bytearray of
        length 16 or more.

        The memory unit for the value of *protect_from* is 16 byte,
        thus with ``protect_from=2`` bytes 0 to 31 are not protected.
        If *protect_from* is zero (the default value) and the Tag has
        valid NDEF management data, the NDEF RW Flag is set to read
        only.

        """
        return super(FelicaLite, self).protect(
            password, read_protect, protect_from)

    def _protect(self, password, read_protect, protect_from):
        if password and len(password) < 16:
            raise ValueError("password must be at least 16 byte")

        if protect_from < 0:
            raise ValueError("protect_from can not be negative")

        if read_protect:
            log.info("this tag can not be made read protected")
            return False

        # The memory configuration block contains access permissions
        # and ndef compatibility information.
        mc = self.read_without_mac(0x88)

        if password is not None:
            if mc[2] != 0xFF:
                log.info("system block protected, can't write key")
                return False

            # if password is empty use factory key of 16 zero bytes
            key = password[0:16] if password else b"\0"*16

            log.debug("protect with key %s", hexlify(key).decode())
            self.write_without_mac(key[7::-1] + key[15:7:-1], 0x87)

        if protect_from < 14:
            log.debug("write protect blocks {0}--13".format(protect_from))
            mc[0:2] = pack("<H", 0x7FFF ^ (2**14 - 2**protect_from))

        if protect_from == 0 and self.ndef is not None:
            attribute_data = self.read_without_mac(0)
            attribute_data[10] = 0x00
            attribute_data[14:16] = pack('>H', sum(attribute_data[0:14]))
            self.write_without_mac(attribute_data, 0)

        log.debug("write protect system blocks 82,83,84,86,87")
        mc[2] = 0x00  # set system blocks 82,83,84,86,87 to read only

        log.debug("write memory configuration %s", hexlify(mc).decode())
        self.write_without_mac(mc, 0x88)
        return True

    def authenticate(self, password):
        """Authenticate a FeliCa Lite Tag.

        A FeliCa Lite Tag is authenticated by a procedure that allows
        both the reader and the tag to calculate a session key from a
        random challenge send by the reader and a key that is securely
        stored on the tag and provided to :meth:`authenticate` as the
        *password* argument. If the tag was protected with an earlier
        call to :meth:`protect` then the same password should
        successfully authenticate.

        After authentication the :meth:`read_with_mac` method can be
        used to read data such that it can not be falsified on
        transmission.

        """
        return super(FelicaLite, self).authenticate(password)

    def _authenticate(self, password):
        if password and len(password) < 16:
            raise ValueError("password must be at least 16 byte")

        # Perform internal authentication, i.e. ensure that the tag
        # has the same card key as in password. If the password is
        # empty, we'll try with the factory key.
        key = b"\0" * 16 if not password else password[0:16]

        log.debug("authenticate with key {}".format(hexlify(key).decode()))
        self._authenticated = False
        self.read_from_ndef_service = self.read_without_mac
        self.write_to_ndef_service = self.write_without_mac

        # Internal authentication starts with a random challenge (rc1 || rc2)
        # that we write to the rc block. Because the tag works little endian,
        # we reverse the order of rc1 and rc2 bytes when writing.
        rc = os.urandom(16)
        log.debug("rc1 = {}".format(hexlify(rc[:8]).decode()))
        log.debug("rc2 = {}".format(hexlify(rc[8:]).decode()))
        self.write_without_mac(rc[7::-1] + rc[15:7:-1], 0x80)

        # The session key becomes the 3DES encryption of the random
        # challenge under the card key and with an initialization vector of
        # all zero.
        sk = FelicaStandard._encrypt_3des_cbc(rc, key, b"\x00" * 8)
        log.debug("sk1 = {}".format(hexlify(sk[:8]).decode()))
        log.debug("sk2 = {}".format(hexlify(sk[8:]).decode()))

        # By reading the id and mac block together we get the mac that the
        # tag has generated over the id block data under it's session key
        # generated the same way as we did) and with rc1 as the
        # initialization vector.
        data = self.read_without_mac(0x82, 0x81)

        # Now we check if we calculate the same mac with our session key.
        # Note that, because of endianess, data must be reversed in chunks
        # of 8 bytes as does the 8 byte mac - this is all done within the
        # generate_mac() function.
        if data[-16:-8] == self.generate_mac(data[0:-16], sk, iv=rc[0:8]):
            log.debug("tag authentication completed")
            self._sk = sk
            self._iv = rc[0:8]
            self._authenticated = True
            self.read_from_ndef_service = self.read_with_mac
        else:
            log.debug("tag authentication failed")

        return self._authenticated

    def format(self, version=0x10, wipe=None):
        """Format a FeliCa Lite Tag for NDEF.

        """
        return super(FelicaLite, self).format(version, wipe)

    def _format(self, version, wipe):
        assert type(version) is int
        assert wipe is None or type(wipe) is int

        if version and version >> 4 != 1:
            log.error("type 3 tag ndef mapping major version must be 1")
            return False

        # The memory configuration block contains access permissions
        # and ndef compatibility information.
        mc = self.read_without_mac(0x88)

        if mc[0] & 0x01 != 0x01:
            log.info("the first user data block is not writeable")
            return False

        if not mc[3] & 0x01:  # ndef compatibility flag
            if mc[2] == 0xFF:  # mc block is writeable
                mc[3] = mc[3] | 0x01
                self.write_without_mac(mc, 0x88)
            else:
                log.info("this tag can no longer be changed to ndef")
                return False

        # Count the number of writeable data blocks (that is excluding
        # the attribute block) from the least significant read/write
        # permission bits that are consecutively set to 1.
        rw_bits = unpack("<H", mc[0:2])[0]
        for nmaxb in range(14):
            if rw_bits >> (nmaxb + 1) & 1 == 0:
                break

        # Create and write the attribute data. Version number, Nbr and
        # Nbw are fix and we have just determined Nmaxb.
        attribute_data = bytearray(16)
        attribute_data[:14] = pack(">BBBHxxxxxBxxx", version, 4, 1, nmaxb, 1)
        attribute_data[14:] = pack(">H", sum(attribute_data[:14]))
        log.debug("set ndef attributes %s", hexlify(attribute_data).decode())
        self.write_without_mac(attribute_data, 0)

        # Overwrite the ndef message area if a wipe is requested.
        if wipe is not None:
            data = bytearray(16 * [wipe])
            for block in range(1, nmaxb+1):
                self.write_without_mac(data, block)

        return True

    def read_without_mac(self, *blocks):
        """Read a number of data blocks without integrity check.

        This method accepts a variable number of integer arguments as
        the block numbers to read. The blocks are read with service
        code 0x000B (NDEF).

        Tag command errors raise :exc:`~nfc.tag.TagCommandError`.

        """
        log.debug("read {0} block(s) without mac".format(len(blocks)))
        service_list = [tt3.ServiceCode(0, 0b001011)]
        block_list = [tt3.BlockCode(n) for n in blocks]
        return self.read_without_encryption(service_list, block_list)

    def read_with_mac(self, *blocks):
        """Read a number of data blocks with integrity check.

        This method accepts a variable number of integer arguments as
        the block numbers to read. The blocks are read with service
        code 0x000B (NDEF). Along with the requested block data the
        tag returns a message authentication code that is verified
        before data is returned. If verification fails the return
        value of :meth:`read_with_mac` is None.

        A :exc:`RuntimeError` exception is raised if the tag was not
        authenticated before calling this method.

        Tag command errors raise :exc:`~nfc.tag.TagCommandError`.

        """
        log.debug("read {0} block(s) with mac".format(len(blocks)))

        if self._sk is None or self._iv is None:
            raise RuntimeError("authentication required")

        service_list = [tt3.ServiceCode(0, 0b001011)]
        block_list = [tt3.BlockCode(n) for n in blocks]
        block_list.append(tt3.BlockCode(0x81))

        data = self.read_without_encryption(service_list, block_list)
        data, mac = data[0:-16], data[-16:-8]
        if mac != self.generate_mac(data, self._sk, self._iv):
            log.warning("mac verification failed")
        else:
            return data

    def write_without_mac(self, data, block):
        """Write a data block without integrity check.

        This is the standard write method for a FeliCa Lite. The
        16-byte string or bytearray *data* is written to the numbered
        *block* in service 0x0009 (NDEF write service). ::

            data = bytearray(range(16)) # 0x00, 0x01, ... 0x0F
            try: tag.write_without_mac(data, 5) # write block 5
            except nfc.tag.TagCommandError:
                print("something went wrong")

        Tag command errors raise :exc:`~nfc.tag.TagCommandError`.

        """
        # Write a single data block without a mac. Write with mac is
        # only supported by FeliCa Lite-S.
        assert len(data) == 16 and type(block) is int
        log.debug("write 1 block without mac".format())
        sc_list = [tt3.ServiceCode(0, 0b001001)]
        bc_list = [tt3.BlockCode(block)]
        self.write_without_encryption(sc_list, bc_list, data)


class FelicaLiteS(FelicaLite):
    """FeliCa Lite-S is a version of FeliCa Lite with enhanced security
    functions. It provides mutual authentication were both the tag and
    the reader must demonstrate posession of the card key before data
    writes can be made. It is also possible to require mutual
    authentication for data reads.

    """
    IC_CODE_MAP = {
        0xF1: "FeliCa Lite-S (RC-S966)",
        0xF2: "FeliCa Link (RC-S730) Lite-S Mode",
    }

    class NDEF(FelicaLite.NDEF):
        def _read_attribute_data(self):
            log.debug("FelicaLiteS.read_attribute_data")
            attributes = super(FelicaLiteS.NDEF, self)._read_attribute_data()
            if attributes is not None and self._tag._authenticated:
                # when authenticated and user data is writeable
                mc = self._tag.read_without_mac(0x88)
                rw_bits = unpack("<H", mc[0:2])[0]
                self._writeable = bool(rw_bits & 0x3ff == 0x3ff)
            return attributes

    def __init__(self, clf, target):
        super(FelicaLiteS, self).__init__(clf, target)
        self._product = self.IC_CODE_MAP[self.pmm[1]]

    def dump(self):
        def oprint(octets):
            return ' '.join(['%02x' % x for x in octets])

        lines = super(FelicaLiteS, self).dump()

        text = ("WCNT[3]", "MAC_A[8]", "STATE")
        config = dict(zip(range(0x90, 0x90+len(text)), text))

        for i in sorted(config.keys()):
            try:
                data = self.read_without_mac(i)
            except tt3.Type3TagCommandError:
                lines.append("{0:3}: {1}({2})".format(
                    i, 16 * "?? ", config[i]))
            else:
                lines.append("{0:3}: {1} ({2})".format(
                    i, oprint(data), config[i]))

        return lines

    def protect(self, password=None, read_protect=False, protect_from=0):
        """Protect a FeliCa Lite-S Tag.

        A FeliCa Lite-S Tag can be write and read protected with a
        custom password (or the default manufacturer key if the
        password is an empty string or bytearray). Note that the
        *read_protect* flag is only evaluated when a *password* is
        provided.

        A non-empty *password* must provide at least 128 bit key
        material, in other words it must be a string or bytearray of
        length 16 or more.

        The memory unit for the value of *protect_from* is 16 byte,
        thus with ``protect_from=2`` bytes 0 to 31 are not protected.
        If *protect_from* is zero (the default value) and the Tag has
        valid NDEF management data, the NDEF RW Flag is set to read
        only.

        """
        return super(FelicaLite, self).protect(
            password, read_protect, protect_from)

    def _protect(self, password, read_protect, protect_from):
        if password and len(password) < 16:
            raise ValueError("password must be at least 16 byte")

        if protect_from < 0:
            raise ValueError("protect_from can not be negative")

        # The memory configuration block contains access permissions
        # and ndef compatibility information.
        mc = self.read_without_mac(0x88)

        if password is not None:
            if mc[2] != 0xFF:  # system block protected
                if mc[5] & 1 == 0:  # key change disabled
                    log.info("card key can not be changed")
                    return False
                if self._authenticated is False:
                    log.info("authentication required to change key")
                    return False

            # if password is empty use factory key of 16 zero bytes
            key = password[0:16].encode("ascii") if password else b'\0' * 16

            log.debug("protect with key %s", hexlify(key).decode())
            ckv = self.read_without_mac(0x86)
            ckv = min(unpack("<H", ckv[0:2])[0] + 1, 0xffff)
            log.debug("new card key version is {0}".format(ckv))
            self.write_without_mac(pack("<H", ckv) + b"\0" * 14, 0x86)
            self.write_without_mac(key[7::-1] + key[15:7:-1], 0x87)

            if not self.authenticate(key):
                log.error("failed to authenticate with new card key")
                return False

            if read_protect and protect_from < 14:
                log.debug("read protect blocks {0}--13".format(protect_from))
                protect_mask = pack("<H", 2**14 - 2**protect_from)
                mc[6:8] = protect_mask

        if protect_from < 14:
            log.debug("write protect blocks {0}--13".format(protect_from))
            protect_mask = pack("<H", 2**14 - 2**protect_from)
            mc[8:10] = mc[10:12] = protect_mask

        if protect_from == 0 and self.ndef is not None:
            attribute_data = self.read_without_mac(0)
            attribute_data[10] = 0x00
            attribute_data[14:16] = pack('>H', sum(attribute_data[0:14]))
            self.write_without_mac(attribute_data, 0)

        log.debug("write protect system blocks 82,83,84,86,87")
        mc[2] = 0x00  # set system blocks 82,83,84,86,87 to read only
        mc[5] = 0x01  # but allow write with mac to ck and ckv block

        # Write the new memory control block.
        log.debug("write memory configuration %s", hexlify(mc).decode())
        self.write_without_mac(mc, 0x88)
        return True

    def authenticate(self, password):
        """Mutually authenticate with a FeliCa Lite-S Tag.

        FeliCa Lite-S supports enhanced security functions, one of
        them is the mutual authentication performed by this
        method. The first part of mutual authentication is to
        authenticate the tag with :meth:`FelicaLite.authenticate`. If
        successful, the shared session key is used to generate the
        integrity check value for write operation to update a specific
        memory block. If that was successful then the tag is ensured
        that the reader has the correct card key.

        After successful authentication the
        :meth:`~FelicaLite.read_with_mac` and :meth:`write_with_mac`
        methods can be used to read and write data such that it can
        not be falsified on transmission.

        """
        if super(FelicaLiteS, self).authenticate(password):
            # At this point we have achieved internal authentication,
            # i.e we know that the tag has the same card key as in
            # password. We now reset the authentication status and do
            # external authentication to assure the tag that we have
            # the right card key.
            self._authenticated = False
            self.read_from_ndef_service = self.read_without_mac
            self.write_to_ndef_service = self.write_without_mac

            # To authenticate to the tag we write a 01h into the
            # ext_auth byte of the state block (block 0x92). The other
            # bytes of the state block can be all set to zero.
            self.write_with_mac(b"\x01" + 15*b"\0", 0x92)

            # Now read the state block and check the value of the
            # ext_auth to see if we are authenticated. If it's 01h
            # then we are, otherwise not.
            if self.read_with_mac(0x92)[0] == 0x01:
                log.debug("mutual authentication completed")
                self._authenticated = True
                self.read_from_ndef_service = self.read_with_mac
                self.write_to_ndef_service = self.write_with_mac
            else:
                log.debug("mutual authentication failed")

        return self._authenticated

    def write_with_mac(self, data, block):
        """Write one data block with additional integrity check.

        If prior to calling this method the tag was not authenticated,
        a :exc:`RuntimeError` exception is raised.

        Command execution errors raise :exc:`~nfc.tag.TagCommandError`.

        """
        # Write a single data block protected with a mac. The card
        # will only accept the write if it computed the same mac.
        log.debug("write 1 block with mac")
        if len(data) != 16:
            raise ValueError("data must be 16 octets")
        if type(block) is not int:
            raise ValueError("block number must be int")
        if self._sk is None or self._iv is None:
            raise RuntimeError("tag must be authenticated first")

        # The write count is the first three byte of the wcnt block.
        wcnt = self.read_without_mac(0x90)[0:3]
        log.debug("write count is %s", hexlify(wcnt[::-1]).decode())

        # We must generate the mac_a block to write the data. The data
        # to encrypt to the mac is composed of write count and block
        # numbers (8 byte) and the data we want to write. The mac for
        # write must be generated with the key flipped (sk2 || sk1).
        def flip(sk):
            return sk[8:16] + sk[0:8]

        data = wcnt + b"\x00" + bytearray([block]) + b"\x00\x91\x00" + data
        maca = self.generate_mac(data, flip(self._sk), self._iv) + wcnt+5*b"\0"

        # Now we can write the data block with our computed mac to the
        # desired block and the maca block. Write without encryption
        # means that the data is not encrypted with a service key.
        sc_list = [tt3.ServiceCode(0, 0b001001)]
        bc_list = [tt3.BlockCode(block), tt3.BlockCode(0x91)]
        self.write_without_encryption(sc_list, bc_list, data[8:24] + maca)


class FelicaPlug(tt3.Type3Tag):
    """FeliCa Plug is a contactless communication interface module for
    microcontrollers.

    """
    IC_CODE_MAP = {
        0xE0: "FeliCa Plug (RC-S926)",
        0xE1: "FeliCa Link (RC-S730) Plug Mode",
    }

    def __init__(self, clf, target):
        super(FelicaPlug, self).__init__(clf, target)
        self._product = self.IC_CODE_MAP[self.pmm[1]]

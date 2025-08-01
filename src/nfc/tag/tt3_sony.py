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

import os
import struct
import random
from binascii import hexlify
from pyDes import triple_des, CBC, des
from struct import pack, unpack
import itertools

import logging
log = logging.getLogger(__name__)

# Constants
BLOCK_SIZE = 8
DATA_BLOCK_SIZE = 16
IV_ZEROS = b"\x00" * BLOCK_SIZE
XOR_MASK = b"\xff" * BLOCK_SIZE
PADDING_BLOCK_SIZE = 6

# Command codes
CMD_AUTH1 = 0x10
CMD_AUTH2 = 0x12
CMD_READ = 0x14
CMD_WRITE = 0x16
CMD_REGISTER_ISSUE_ID = 0x80
CMD_REGISTER_AREA = 0x82
CMD_REGISTER_SERVICE = 0x84
CMD_COMMIT_REGISTRATION = 0x8E

# Status codes
STATUS_SUCCESS = 0x00


class CryptoUtils:
    """Utility class for cryptographic operations."""

    @staticmethod
    def _normalize_result(result: bytes | str) -> bytes:
        """Normalize encryption/decryption result to bytes."""
        if isinstance(result, bytes):
            return result
        elif isinstance(result, str):
            return result.encode("latin-1")
        else:
            return bytes(result)

    @staticmethod
    def encrypt_des(data: bytes, key: bytes) -> bytes:
        """Encrypt data using DES in CBC mode."""
        cipher = des(key, mode=CBC, IV=IV_ZEROS)
        result = cipher.encrypt(data)
        return CryptoUtils._normalize_result(result)

    @staticmethod
    def decrypt_des(data: bytes, key: bytes) -> bytes:
        """Decrypt data using DES in CBC mode."""
        cipher = des(key, mode=CBC, IV=IV_ZEROS)
        result = cipher.decrypt(data)
        return CryptoUtils._normalize_result(result)

    @staticmethod
    def encrypt_3des(data: bytes, key1: bytes, key2: bytes) -> bytes:
        """Encrypt data using 3DES with two keys."""
        triple_key = key1 + key2 + key1
        cipher = triple_des(triple_key)
        result = cipher.encrypt(data)
        return CryptoUtils._normalize_result(result)

    @staticmethod
    def decrypt_3des(data: bytes, key1: bytes, key2: bytes) -> bytes:
        """Decrypt data using 3DES with two keys."""
        triple_key = key1 + key2 + key1
        cipher = triple_des(triple_key)
        result = cipher.decrypt(data)
        return CryptoUtils._normalize_result(result)

    @staticmethod
    def xor_bytes(a: bytes, b: bytes) -> bytes:
        """XOR two byte arrays of equal length."""
        if len(a) != len(b):
            raise ValueError(f"Byte arrays must be equal length: {len(a)} != {len(b)}")
        return bytes(x ^ y for x, y in zip(a, b))


class KeyManager:
    """Manages key generation and derivation."""

    @staticmethod
    def generate_service_keys(
        system_key: bytes, area_keys: list[bytes], service_keys: list[bytes]
    ) -> tuple[bytes, bytes]:
        """
        Generate Group Service Key (GSK) and User Service Key (USK).

        Args:
            system_key: Base system key
            area_keys: List of area keys for encryption chain
            service_keys: List of service keys for encryption chain

        Returns:
            Tuple of (group_service_key, user_service_key)
        """
        current_key = system_key

        # Apply area keys
        for area_key in area_keys:
            current_key = CryptoUtils.encrypt_des(current_key, area_key)

        group_service_key = current_key

        # Apply service keys
        for service_key in service_keys:
            current_key = CryptoUtils.encrypt_des(current_key, service_key)

        user_service_key = current_key

        return group_service_key, user_service_key

    @staticmethod
    def generate_package(package_plain: bytes, package_key: bytes) -> bytes:
        """
        Generate encrypted package with MAC.

        Args:
            package_plain: Plain package data
            package_key: Key for package encryption

        Returns:
            Encrypted package with MAC
        """
        if len(package_plain) % BLOCK_SIZE != 0:
            raise ValueError(f"Package data must be multiple of {BLOCK_SIZE} bytes")

        # Generate MAC
        mac_key = CryptoUtils.xor_bytes(package_key, XOR_MASK)
        mac = CryptoUtils.encrypt_des(package_plain, mac_key)[-BLOCK_SIZE:]

        # Encrypt package with MAC
        package_with_mac = package_plain + mac
        encrypted_package = CryptoUtils.encrypt_des(package_with_mac, package_key)

        return encrypted_package


def activate(clf, target):
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

    def __init__(self, clf, target):
        super(FelicaStandard, self).__init__(clf, target)
        self._product = "FeliCa Standard ({0})".format(
            self.IC_CODE_MAP[self.pmm[1]][0])
        
        self.transaction_id: bytes = b""
        self.transaction_key: bytes = b""
        self.transaction_number: int = 0
        self._authenticated_standard: bool = False

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

        Command execution errors raise :exc:`~nfc.tag.TagCommandError`.

        """
        a, b, e = self.pmm[2] & 7, self.pmm[2] >> 3 & 7, self.pmm[2] >> 6
        timeout = 302E-6 * ((b + 1) * len(service_list) + a + 1) * 4**e
        pack = lambda x: x.pack()  # noqa: E731
        data = bytearray([len(service_list)]) \
            + b''.join(map(pack, service_list))
        data = self.send_cmd_recv_rsp(0x02, data, timeout, check_status=False)
        if len(data) != 1 + len(service_list) * 2:
            log.debug("insufficient data received from tag")
            raise tt3.Type3TagCommandError(tt3.DATA_SIZE_ERROR)
        return [unpack("<H", data[i:i+2])[0] for i in range(1, len(data), 2)]
    
    def request_service_v2(self, service_list):
        """Verify existence of services (or areas) and get key versions with crypto support.

        Each service (or area) to verify must be given as a
        :class:`~nfc.tag.tt3.ServiceCode` in the iterable
        *service_list*. 
        
        The key versions are returned as a list of tuples in the order requested.
        For crypto_id 0x41 or 0x43 (dual crypto support), each tuple contains
        (aes_key_version, des_key_version). For other crypto_ids, each tuple 
        contains (key_version, None).
        
        If a specified service (or area) does not exist, the behavior depends
        on the card's response format.

        Command execution errors raise :exc:`~nfc.tag.TagCommandError`.

        """
        a, b, e = self.pmm[2] & 7, self.pmm[2] >> 3 & 7, self.pmm[2] >> 6
        timeout = 302E-6 * ((b + 1) * len(service_list) + a + 1) * 4**e
        pack = lambda x: x.pack()  # noqa: E731
        data = bytearray([len(service_list)]) \
            + b''.join(map(pack, service_list))
        data = self.send_cmd_recv_rsp(0x32, data, timeout, check_status=False)
        
        key_versions: list[tuple[int, int | None]] = []
        st1 = data[0]
        if st1 == 0:
            crypto_id = data[2]
            node_count = data[3]
            if crypto_id == 0x41 or crypto_id == 0x43:
                for i in range(node_count):
                    aes_offset = 4 + i * 2
                    des_offset = node_count * 2 + aes_offset
                    key_versions.append(
                        (
                            int.from_bytes(data[aes_offset:aes_offset + 2], byteorder="little"),
                            int.from_bytes(data[des_offset:des_offset + 2], byteorder="little"),
                        )
                    )
            else:
                for i in range(node_count):
                    offset = 4 + i * 2
                    key_versions.append((int.from_bytes(data[offset:offset + 2], byteorder="little"), None))
        return key_versions

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
        a, b, e = self.pmm[3] & 7, self.pmm[3] >> 3 & 7, self.pmm[3] >> 6
        timeout = 302E-6 * (b + 1 + a + 1) * 4**e
        data = self.send_cmd_recv_rsp(0x04, b'', timeout, check_status=False)
        if len(data) != 1:
            log.debug("insufficient data received from tag")
            raise tt3.Type3TagCommandError(tt3.DATA_SIZE_ERROR)
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
        a, e = self.pmm[3] & 7, self.pmm[3] >> 6
        timeout = max(302E-6 * (a + 1) * 4**e, 0.002)
        data = pack("<H", service_index)
        data = self.send_cmd_recv_rsp(0x0A, data, timeout, check_status=False)
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
        a, e = self.pmm[3] & 7, self.pmm[3] >> 6
        timeout = max(302E-6 * (a + 1) * 4**e, 0.002)
        data = self.send_cmd_recv_rsp(0x0C, b'', timeout, check_status=False)
        if len(data) != 1 + data[0] * 2:
            log.debug("insufficient data received from tag")
            raise tt3.Type3TagCommandError(tt3.DATA_SIZE_ERROR)
        return [unpack(">H", data[i:i+2])[0] for i in range(1, len(data), 2)]

    def _check_packet_mac(self, data: bytes, expected_response_code: int) -> bool:
        """
        Verify packet MAC for encrypted responses.
        
        Args:
            data: Encrypted response data with MAC
            expected_response_code: Expected response code (command_code + 1)
            
        Returns:
            True if MAC is valid, False otherwise
        """
        try:
            if len(data) % BLOCK_SIZE != 0:
                return False
                
            if len(data) < BLOCK_SIZE:
                return False
            
            # Extract MAC (last 8 bytes)
            mac = data[-BLOCK_SIZE:]
            
            # Split remaining data into 8-byte blocks
            payload = data[:-BLOCK_SIZE]
            if len(payload) == 0:
                return False
                
            blocks = [payload[i:i+BLOCK_SIZE] for i in range(0, len(payload), BLOCK_SIZE)]
            
            # Verify MAC: decrypt in reverse order using blocks as keys
            x = mac
            for block in reversed(blocks):
                x = CryptoUtils.decrypt_des(x, block)
            
            # For encrypted responses: x[0] = data_length + 2, x[1] = response_code
            expected_length = len(data) + 2
            
            return (len(x) >= 2 and 
                    x[0] == expected_length and 
                    x[1] == expected_response_code)
                    
        except Exception:
            return False

    def mutual_authentication(
        self,
        areas: list[int],
        services: list[int], 
        group_service_key: bytes,
        user_service_key: bytes,
    ) -> tuple[str, str]:
        """
        Perform mutual authentication with the card.
        
        Args:
            areas: List of area codes
            services: List of service codes
            group_service_key: Group service key
            user_service_key: User service key
            
        Returns:
            Tuple of (issue_id_hex, issue_parameter_hex)
        """
        try:
            idm = bytes(self.idm)

            # Generate random challenge
            random_1 = random.randbytes(BLOCK_SIZE)
            
            # Calculate authentication parameters
            L = CryptoUtils.xor_bytes(group_service_key, idm)
            alpha = CryptoUtils.encrypt_des(user_service_key, L)
            beta = CryptoUtils.encrypt_des(L, alpha)
            
            challenge_1A = CryptoUtils.encrypt_3des(random_1, alpha, L)
            
            # Build authentication command
            auth1_cmd = self._build_auth1_command(areas, services, challenge_1A)
            
            # Execute first authentication
            a, b, e = self.pmm[4] & 7, self.pmm[4] >> 3 & 7, self.pmm[4] >> 6
            auth1_timeout = 302E-6 * ((b + 1) * (len(areas) + len(services)) + a + 1) * 4**e
            auth1_rsp = self.send_cmd_recv_rsp(CMD_AUTH1, auth1_cmd, auth1_timeout, check_status=False)
            
            # Process authentication response
            challenge_1B = auth1_rsp[0:8]
            challenge_2A = auth1_rsp[8:16]
            
            # Verify challenge response
            expected_1B = CryptoUtils.encrypt_3des(random_1, L, beta)
            if expected_1B != challenge_1B:
                raise tt3.Type3TagCommandError(0x1001)  # Authentication failed
                
            # Generate second challenge response
            random_2 = CryptoUtils.decrypt_3des(challenge_2A, L, beta)
            challenge_2B = CryptoUtils.encrypt_3des(random_2, alpha, L)
            
            # Execute second authentication
            auth2_cmd = idm + challenge_2B
            a, b, e = self.pmm[4] & 7, self.pmm[4] >> 3 & 7, self.pmm[4] >> 6
            auth2_timeout = max(302E-6 * (a + 1) * 4**e, 0.002)
            auth2_rsp = self.send_cmd_recv_rsp(CMD_AUTH2, auth2_cmd, auth2_timeout, send_idm=False)
            
            # Process final authentication response
            return self._process_auth2_response(auth2_rsp, random_1, random_2)
            
        except Exception as e:
            if isinstance(e, tt3.Type3TagCommandError):
                raise
            raise tt3.Type3TagCommandError(0x1001)  # Authentication failed

    def _build_auth1_command(
        self, areas: list[int], services: list[int], challenge_1A: bytes
    ) -> bytes:
        """Build authentication command 1."""
        # Add areas
        cmd = len(areas).to_bytes(1, "little")
        for area in areas:
            cmd += area.to_bytes(2, "little")
            
        # Add services
        cmd += len(services).to_bytes(1, "little")
        for service in services:
            cmd += service.to_bytes(2, "little")
            
        cmd += challenge_1A
        return cmd

    def _process_auth2_response(
        self, auth2_rsp: bytes, random_1: bytes, random_2: bytes
    ) -> tuple[str, str]:
        """Process authentication 2 response."""
        # Set transaction parameters
        self.transaction_id = random_1[2:]
        self.transaction_key = random_2
        
        # Decrypt response
        rsp_plain = CryptoUtils.decrypt_des(auth2_rsp, self.transaction_key)
        
        # Verify MAC
        if not self._check_packet_mac(rsp_plain, CMD_AUTH2 + 1):
            raise tt3.Type3TagCommandError(0x1004)  # MAC verification failed
            
        # Extract transaction number and verify transaction ID
        self.transaction_number = int.from_bytes(rsp_plain[0:2], "little")
        
        if rsp_plain[2:8] != self.transaction_id:
            raise tt3.Type3TagCommandError(0x1001)  # Authentication failed
            
        # Extract issue information
        issue_id = rsp_plain[8:16]
        issue_parameter = rsp_plain[16:24]
        
        self._authenticated_standard = True
        
        return issue_id.hex(), issue_parameter.hex()

    def _encryption_exchange(self, cmd_code: int, data: bytes, timeout: float) -> bytes:
        """
        Perform encrypted command exchange.
        
        Args:
            cmd_code: Command code
            data: Data payload
            
        Returns:
            Decrypted response data
        """
        if not self._authenticated_standard:
            raise tt3.Type3TagCommandError(0x1001)  # Authentication required
            
        self.transaction_number += 1
        
        if self.transaction_number >= 0xFFFF:
            raise tt3.Type3TagCommandError(0x1005)  # Transaction number overflow
            
        # Prepare data with transaction info
        payload = (
            self.transaction_number.to_bytes(2, "little") + 
            self.transaction_id + 
            data
        )
        
        # Add padding if necessary
        payload = self._add_padding(payload)
        
        # Calculate MAC
        mac = self._calculate_command_mac(cmd_code, payload)
        payload_with_mac = payload + mac
        
        # Encrypt and send
        encrypted_data = CryptoUtils.encrypt_des(payload_with_mac, self.transaction_key)
        encrypted_response = self.send_cmd_recv_rsp(cmd_code, encrypted_data, timeout, send_idm=False)
        
        # Decrypt response
        response = CryptoUtils.decrypt_des(encrypted_response, self.transaction_key)
        
        # Verify response with command code context
        return self._verify_encrypted_response(response, cmd_code)

    def _add_padding(self, data: bytes) -> bytes:
        """Add PKCS#7 padding to data."""
        if len(data) % BLOCK_SIZE == 0:
            return data
            
        pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
        return data + bytes([pad_len] * pad_len)

    def _calculate_command_mac(self, cmd_code: int, payload: bytes) -> bytes:
        """Calculate MAC for command."""
        blocks = [
            payload[i : i + BLOCK_SIZE] for i in range(0, len(payload), BLOCK_SIZE)
        ]
        
        length = 2 + len(payload) + BLOCK_SIZE
        x = length.to_bytes(1, "little") + cmd_code.to_bytes(1, "little") + b"\x00" * 6
        
        for block in blocks:
            x = CryptoUtils.encrypt_des(x, block)
            
        return x

    def _verify_encrypted_response(self, response: bytes, cmd_code: int) -> bytes:
        """Verify and process encrypted response."""
        try:
            # MAC verification for encrypted responses with command code context
            if not self._check_packet_mac(response, cmd_code + 1):
                raise tt3.Type3TagCommandError(0x1004)  # MAC verification failed
                
            # Verify transaction number
            response_number = int.from_bytes(response[0:2], "little")
            if response_number <= self.transaction_number:
                raise tt3.Type3TagCommandError(0x1003)  # Transaction error
                
            # Verify transaction ID
            if response[2:8] != self.transaction_id:
                raise tt3.Type3TagCommandError(0x1003)  # Transaction error
                
            self.transaction_number = response_number
            return response[8:]
            
        except Exception as e:
            if isinstance(e, tt3.Type3TagCommandError):
                raise
            raise tt3.Type3TagCommandError(0x1004)  # MAC verification failed

    def _elements_to_bytes(self, elements: list[tuple[int, int]]) -> bytes:
        """Convert element list to byte representation."""
        result = b""
        for index, number in elements:
            if index >= 16:
                raise ValueError(f"Element index must be < 16, got {index}")
            result += (0x80 | index).to_bytes(1, "little") + number.to_bytes(1, "little")
        return result

    def read_blocks(self, elements: list[tuple[int, int]]) -> list[bytes]:
        """
        Read data blocks from card.
        
        Args:
            elements: List of (service_index, block_number) tuples
            
        Returns:
            List of 16-byte data blocks
        """
        if not elements:
            raise ValueError("Elements list cannot be empty")
            
        cmd = len(elements).to_bytes(1, "little") + self._elements_to_bytes(elements)
        a, b, e = self.pmm[5] & 7, self.pmm[5] >> 3 & 7, self.pmm[5] >> 6
        timeout = 302E-6 * ((b + 1) * len(elements) + a + 1) * 4**e

        try:
            response = self._encryption_exchange(CMD_READ, cmd, timeout)
            
            status_flag1, status_flag2 = response[0], response[1]
            if status_flag1 != STATUS_SUCCESS:
                raise tt3.Type3TagCommandError(0x1002)  # Card operation error
                
            if response[2] != len(elements):
                raise tt3.Type3TagCommandError(0x1006)  # Invalid response format
                
            block_data = response[3:]
            return [
                block_data[i * DATA_BLOCK_SIZE : (i + 1) * DATA_BLOCK_SIZE]
                for i in range(len(elements))
            ]
            
        except Exception as e:
            if isinstance(e, tt3.Type3TagCommandError):
                raise
            raise tt3.Type3TagCommandError(0x1002)  # Card operation error

    def write_blocks(self, elements_data: dict[tuple[int, int], bytes]) -> None:
        """
        Write data blocks to card.
        
        Args:
            elements_data: Dictionary mapping (service_index, block_number) to 16-byte data
        """
        if not elements_data:
            raise ValueError("Elements data cannot be empty")
            
        # Validate data blocks
        for element, data in elements_data.items():
            if len(data) != DATA_BLOCK_SIZE:
                raise ValueError(
                    f"Data block must be {DATA_BLOCK_SIZE} bytes, got {len(data)}"
                )
                
        # Build command
        cmd = len(elements_data).to_bytes(1, "little")
        cmd += self._elements_to_bytes(list(elements_data.keys()))
        
        for data in elements_data.values():
            cmd += data

        a, b, e = self.pmm[6] & 7, self.pmm[6] >> 3 & 7, self.pmm[6] >> 6
        timeout = 302E-6 * ((b + 1) * len(elements_data) + a + 1) * 4**e
            
        try:
            response = self._encryption_exchange(CMD_WRITE, cmd, timeout)
            
            status_flag1, status_flag2 = response[0], response[1]
            if status_flag1 != STATUS_SUCCESS:
                raise tt3.Type3TagCommandError(0x1002)  # Card operation error
                
        except Exception as e:
            if isinstance(e, tt3.Type3TagCommandError):
                raise
            raise tt3.Type3TagCommandError(0x1002)  # Card operation error

    def register_issue_id(
        self,
        system_code: str,
        key_version: int,
        area0_key: bytes,
        issue_id: bytes,
        issue_parameter: bytes,
        package_key: bytes,
    ) -> int:
        """
        Register issue ID on card.
        
        Args:
            system_code: 4-character hex system code
            key_version: Key version number
            area0_key: 8-byte area 0 key
            issue_id: 8-byte issue ID
            issue_parameter: 8-byte issue parameter
            package_key: Package encryption key
            
        Returns:
            Remaining block count
        """
        if len(system_code) != 4:
            raise ValueError("System code must be 4 characters")
        if len(area0_key) != BLOCK_SIZE:
            raise ValueError(f"Area key must be {BLOCK_SIZE} bytes")
        if len(issue_id) != BLOCK_SIZE:
            raise ValueError(f"Issue ID must be {BLOCK_SIZE} bytes")
        if len(issue_parameter) != BLOCK_SIZE:
            raise ValueError(f"Issue parameter must be {BLOCK_SIZE} bytes")
            
        package_plain = (
            bytes.fromhex(system_code)
            + key_version.to_bytes(2, "little")
            + area0_key
            + b"\x00" * 4
        )
        
        package = KeyManager.generate_package(package_plain, package_key)
        cmd = issue_id + issue_parameter + package
        a, e = self.pmm[7] & 7, self.pmm[7] >> 6
        timeout = max(302E-6 * (a + 1) * 4**e, 0.002)

        try:
            response = self._encryption_exchange(CMD_REGISTER_ISSUE_ID, cmd, timeout)
            
            status_flag1, status_flag2 = response[0], response[1]
            if status_flag1 != STATUS_SUCCESS:
                raise tt3.Type3TagCommandError(0x1009)  # Register issue ID failed
                
            return int.from_bytes(response[2:4], "little")
            
        except Exception as e:
            if isinstance(e, tt3.Type3TagCommandError):
                raise
            raise tt3.Type3TagCommandError(0x1009)  # Register issue ID failed

    def register_area(
        self,
        area_code: int,
        service_code_range: tuple[int, int],
        size: int,
        key_version: int,
        area_key: bytes,
        package_key: bytes,
    ) -> None:
        """Register area on card."""
        service_code_begin, service_code_end = service_code_range
        
        if area_code != service_code_begin:
            raise ValueError("Area code must match service code begin")
        if len(area_key) != BLOCK_SIZE:
            raise ValueError(f"Area key must be {BLOCK_SIZE} bytes")
            
        package_plain = (
            service_code_begin.to_bytes(2, "little")
            + service_code_end.to_bytes(2, "little")
            + size.to_bytes(2, "little")
            + key_version.to_bytes(2, "little")
            + area_key
        )
        
        package = KeyManager.generate_package(package_plain, package_key)
        payload = (
            area_code.to_bytes(2, "little") + package + b"\x06" * PADDING_BLOCK_SIZE
        )
        a, e = self.pmm[7] & 7, self.pmm[7] >> 6
        timeout = max(302E-6 * (a + 1) * 4**e, 0.002)
        
        try:
            response = self._encryption_exchange(CMD_REGISTER_AREA, payload, timeout)
            
            status_flag1, status_flag2 = response[0], response[1]
            if status_flag1 != STATUS_SUCCESS:
                raise tt3.Type3TagCommandError(0x1008)  # Area registration failed
                
        except Exception as e:
            if isinstance(e, tt3.Type3TagCommandError):
                raise
            raise tt3.Type3TagCommandError(0x1008)  # Area registration failed

    def register_service(
        self,
        service_code: int,
        size: int,
        key_version: int,
        service_key: bytes,
        package_key: bytes,
    ) -> int:
        """Register service on card."""
        if len(service_key) != BLOCK_SIZE:
            raise ValueError(f"Service key must be {BLOCK_SIZE} bytes")
            
        package_plain = (
            service_code.to_bytes(2, "little")
            + b"\x00" * 2
            + size.to_bytes(2, "little")
            + key_version.to_bytes(2, "little")
            + service_key
        )
        
        package = KeyManager.generate_package(package_plain, package_key)
        payload = (
            service_code.to_bytes(2, "little") + package + b"\x06" * PADDING_BLOCK_SIZE
        )
        a, e = self.pmm[7] & 7, self.pmm[7] >> 6
        timeout = max(302E-6 * (a + 1) * 4**e, 0.002)
        
        try:
            response = self._encryption_exchange(CMD_REGISTER_SERVICE, payload, timeout)
            
            status_flag1, status_flag2 = response[0], response[1]
            if status_flag1 != STATUS_SUCCESS:
                raise tt3.Type3TagCommandError(0x1007)  # Service registration failed
                
            return int.from_bytes(response[2:4], "little")
            
        except Exception as e:
            if isinstance(e, tt3.Type3TagCommandError):
                raise
            raise tt3.Type3TagCommandError(0x1007)  # Service registration failed

    def commit_registration(self) -> None:
        """Commit all pending registrations."""
        a, e = self.pmm[7] & 7, self.pmm[7] >> 6
        timeout = max(302E-6 * (a + 1) * 4**e, 0.002)
        try:
            response = self._encryption_exchange(CMD_COMMIT_REGISTRATION, b"", timeout)
            
            status_flag1, status_flag2 = response[0], response[1]
            if status_flag1 != STATUS_SUCCESS:
                raise tt3.Type3TagCommandError(0x1002)  # Card operation error
                
        except Exception as e:
            if isinstance(e, tt3.Type3TagCommandError):
                raise
            raise tt3.Type3TagCommandError(0x1002)  # Card operation error

    def reset_authentication(self):
        """Reset authentication state."""
        self._authenticated_standard = False
        self.transaction_id = b""
        self.transaction_key = b""
        self.transaction_number = 0


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
        # one string that is then triple des encrypted with key and
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
        return bytearray(triple_des(key, CBC, bytes(iv)).encrypt(txt)[:-9:-1])

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

        # The session key becomes the triple_des encryption of the random
        # challenge under the card key and with an initialization vector of
        # all zero.
        sk = triple_des(key, CBC, b'\00' * 8).encrypt(rc)
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

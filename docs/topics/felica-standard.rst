.. _felica-standard-tutorial:
.. currentmodule:: nfc.tag.tt3_sony

**********************
FeliCa Standard Cards
**********************

.. contents::
   :local:

FeliCa Standard is the range of FeliCa OS based card products with a
file system that holds multiple applications on one card. Beyond the
Type 3 Tag operations that every FeliCa card supports, a Standard card
implements a proprietary command set for inspecting the file system,
for issuance, and for reading and writing services that are protected
by a card key.

A Standard card is activated like any other tag and yields a
:class:`FelicaStandard` instance. ::

   import nfc

   clf = nfc.ContactlessFrontend('usb')
   tag = clf.connect(rdwr={'on-connect': lambda tag: False})

   if isinstance(tag, nfc.tag.tt3_sony.FelicaStandard):
       print(tag.product)

All commands raise :exc:`~nfc.tag.TagCommandError` when the card
answers with an error status or with a malformed response. Arguments
that can not produce a valid command frame raise :exc:`ValueError`
before anything is sent.

Card and file system information
================================

None of the commands in this section require authentication.

The services and areas of a system are enumerated with
:meth:`~FelicaStandard.request_code_list`, which walks the node tree of
a parent node in chunks. The *continue* flag of the return value tells
whether more entries follow at the next index. ::

   more, areas, services = tag.request_code_list(0x0000, 0)
   for area_code, area_last in areas:
       print("Area {0:04X}--{1:04X}".format(area_code, area_last))
   for service_code in services:
       print("Service {0:04X}".format(service_code))

The number of blocks assigned to a node, and how many of them are
still free, is reported by
:meth:`~FelicaStandard.request_block_information` and
:meth:`~FelicaStandard.request_block_information_ex`. ::

   assigned = tag.request_block_information([0x1008])
   assigned, free = tag.request_block_information_ex([0x1008])

Further information is available with
:meth:`~FelicaStandard.get_area_information`,
:meth:`~FelicaStandard.get_system_status`,
:meth:`~FelicaStandard.get_container_id`,
:meth:`~FelicaStandard.get_container_property`,
:meth:`~FelicaStandard.get_container_issue_information` and
:meth:`~FelicaStandard.request_product_information`.

:meth:`~FelicaStandard.request_specification_version` returns a
:class:`SpecificationVersion` that names the individual option
versions instead of returning them as a bare list. It returns
:const:`None` for a card that does not implement the command. ::

   version = tag.request_specification_version()
   if version is not None:
       print(version.basic_version)
       print(version.des_option_version)
       print(version.random_id_option_version)

The key version of a service is returned by
:meth:`~FelicaStandard.request_service` and, for cards that hold both
an AES and a DES key per node, by
:meth:`~FelicaStandard.request_service_v2`. The first element of the
v2 return value is the crypto identifier of the card; for ``0x41`` and
``0x43`` each key version is an ``(aes_version, des_version)`` pair,
otherwise it is a single integer. ::

   from nfc.tag.tt3 import ServiceCode

   crypto_id, key_versions = tag.request_service_v2([ServiceCode(64, 0x09)])

:meth:`~FelicaStandard.get_node_property` reports per node whether the
value limited purse service (property type ``0x00``) or MAC
communication (property type ``0x01``) is enabled. ::

   for node in tag.get_node_property(0x01, [0x1008]):
       print(node["enabled"])

Node keys and key derivation
============================

Access to a protected service requires the key of that service, which
is not stored on the card in usable form but derived by folding the
key hierarchy from the system key down to the individual service.

For the DES scheme :meth:`~FelicaStandard.generate_service_keys_des`
performs that derivation and returns both the group service key (after
the areas) and the user service key (after the services). ::

   group_key, user_key = nfc.tag.tt3_sony.FelicaStandard \
       .generate_service_keys_des(system_key, [area_key], [service_key])

For the AES-128 scheme the corresponding group key is computed by
:meth:`~FelicaStandard.generate_group_key_v2_aes128` from the ordered
sequence of 16 byte node keys. ::

   group_key = nfc.tag.tt3_sony.FelicaStandard \
       .generate_group_key_v2_aes128([area_key, service_key])

Both are static methods and do not talk to a card.

Secure messaging with DES
=========================

:meth:`~FelicaStandard.mutual_authentication` runs the complete
Authentication1 / Authentication2 exchange, verifies that the card
holds the same key, and opens a secure session. It returns the issue
identifier and issue parameter that the card reports. ::

   from nfc.tag.tt3 import BlockCode, ServiceCode

   issue_id, issue_parameter = tag.mutual_authentication(
       [0x0000], [ServiceCode(64, 0x09)], group_key, user_key)

Once the session is open, :meth:`~FelicaStandard.read` and
:meth:`~FelicaStandard.write` exchange data blocks under it. Every
packet is encrypted and carries a MAC, and the transaction number is
checked to advance on each exchange, so a replayed or reordered
response is rejected. ::

   blocks = tag.read([BlockCode(0), BlockCode(1)])
   tag.write([BlockCode(0)], bytearray(16))

The *data* argument of :meth:`~FelicaStandard.write` must be exactly
16 byte per block code.

Authentication fails with a :exc:`RuntimeError` if the card can not
prove that it holds the key, and with a
:exc:`~nfc.tag.TagCommandError` if a response does not authenticate.
The individual :meth:`~FelicaStandard.authentication1` and
:meth:`~FelicaStandard.authentication2` commands are also available
for callers that drive the handshake themselves.

Secure messaging with AES-128
=============================

Newer cards implement a second secure messaging scheme that uses
AES-128 for encryption and AES-CMAC for authentication. The flow is
the same, with node codes instead of separate area and service lists,
and a 16 byte group and individual key. ::

   issue_id, issue_parameter = tag.mutual_authentication_v2(
       0x00, [0x1008], group_key, individual_key)

   blocks = tag.read_v2([BlockCode(0)])
   tag.write_v2([BlockCode(0)], bytearray(16))

:meth:`~FelicaStandard.authentication1_v2` and
:meth:`~FelicaStandard.authentication2_v2` expose the two halves of
the handshake.

The secure session
==================

:meth:`~FelicaStandard.authenticated_scheme` returns ``"des"`` or
``"aes128"`` while a session is open, and :const:`None` otherwise. The
session itself is held in an :class:`AuthenticatedContext` that can be
read with :meth:`~FelicaStandard.authenticated_context`, installed
with :meth:`~FelicaStandard.set_authenticated_context`, and discarded
with :meth:`~FelicaStandard.clear_authenticated_context`. The context
is copied in and out, so a caller can keep a snapshot without it being
mutated by later commands. ::

   context = tag.authenticated_context()
   tag.clear_authenticated_context()
   # ... later, on the same card ...
   tag.set_authenticated_context(context)

Note that a context only stays valid as long as the card keeps the
session, and that the transaction number must keep advancing. It can
not be reused after the card has been reactivated.

:meth:`~FelicaStandard.secure_transceive` sends an arbitrary command
code and payload through the open session and returns the decrypted
response payload. This is the primitive that
:meth:`~FelicaStandard.read` and :meth:`~FelicaStandard.write` are
built on, and it is exposed for commands that have no typed wrapper. ::

   payload = tag.secure_transceive(0x3A, b'', 0.1)

Because the DES scheme pads to a multiple of 8 byte, a payload
returned for that scheme may carry trailing padding beyond the fields
the command defines.

Issuance
========

The issuance commands all run inside a secure session and take a
*package key* that protects the issuance package.
:meth:`~FelicaStandard.register_issue_id` writes the issue identifier
and the area 0 key, :meth:`~FelicaStandard.register_area` and
:meth:`~FelicaStandard.register_service` add nodes, and
:meth:`~FelicaStandard.change_system_block` commits the system block.
The register commands return the number of blocks still available. ::

   remaining = tag.register_issue_id(
       0x8092, 1, area0_key, issue_id, issue_parameter, package_key)
   tag.register_area(0x1000, (0x1000, 0x1717), 4, 1, area_key, package_key)
   remaining = tag.register_service(0x1008, 4, 1, service_key, package_key)
   tag.change_system_block()

Service keys are rotated with :meth:`~FelicaStandard.change_keys`,
which sends the new key material through the secure Write command.
Each entry needs the parent key, the new key, the old key, and the new
key version. ::

   tag.change_keys([{
       "parent_key": parent_key,
       "new_key": new_key,
       "old_key": old_key,
       "new_key_version": 2,
   }])

.. warning:: The issuance commands change the card permanently. A
   wrong key or an interrupted sequence can leave a card unusable.

Limits
======

The specification bounds the list arguments of the commands above, and
the values are checked before a command frame is built. A list that is
empty or longer than the limit raises :exc:`ValueError`.

======================  =====================================================
Limit                   Applies to
======================  =====================================================
32 service codes        :meth:`~FelicaStandard.request_service`,
                        :meth:`~FelicaStandard.request_service_v2`,
                        the areas and services of
                        :meth:`~FelicaStandard.authentication1`, and the
                        nodes of :meth:`~FelicaStandard.authentication1_v2`
32 node codes           :meth:`~FelicaStandard.request_block_information`,
                        :meth:`~FelicaStandard.request_block_information_ex`
16 node codes           :meth:`~FelicaStandard.get_node_property`
255 block codes         :meth:`~FelicaStandard.read`,
                        :meth:`~FelicaStandard.read_v2`,
                        :meth:`~FelicaStandard.write`,
                        :meth:`~FelicaStandard.write_v2`
======================  =====================================================

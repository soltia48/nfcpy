Changelog for nfcpy
===================

1.1.0 (unreleased)
------------------

This release implements the FeliCa Standard proprietary command set,
including both secure messaging schemes. It also replaces the `pyDes`
dependency with `pycryptodome` and drops support for Python versions
before 3.8.

* The `nfc.tag.tt3_sony.FelicaStandard` class implements the proprietary
  FeliCa Standard commands for card and file system inspection: Request
  Block Information (Ex), Request Code List, Set Parameter, Get Container
  Issue Information, Get Container Property, Get Container ID, Get Area
  Information, Get Node Property, Get System Status, Request Product
  Information, Request Specification Version, Request Service v2, and
  Reset Mode.

* Services protected by a card key can now be used. The
  `mutual_authentication` method performs the DES Authentication1 and
  Authentication2 exchange and opens a secure session for the `read` and
  `write` methods. The `mutual_authentication_v2` method does the same
  for the AES-128 scheme with `read_v2` and `write_v2`. Both sessions
  encrypt every packet, authenticate it with a MAC, and require the
  transaction number to advance.

* The session state is exposed as an `AuthenticatedContext` through the
  `authenticated_context`, `set_authenticated_context` and
  `clear_authenticated_context` methods, so a session can be handed to a
  different tag instance. The `secure_transceive` method sends an
  arbitrary command through an open session.

* Service keys are derived from a key hierarchy with the static methods
  `generate_service_keys_des` and `generate_group_key_v2_aes128`.

* Card issuance is supported with the `register_issue_id`,
  `register_area`, `register_service` and `change_system_block` methods.
  Service keys are rotated with `change_keys`.

* The `pyDes` dependency is replaced by `pycryptodome`, which also
  provides the AES and CMAC primitives needed for the FeliCa Standard
  v2 secure messaging. The Mifare Ultralight C and FeliCa Lite/Lite-S
  authentication produce byte identical results as before. A 16 byte
  Ultralight C key whose halves are equal degenerates to single DES;
  `pycryptodome` refuses to build a 3DES cipher for such a key, so
  `nfc.tag.tt2_nxp.triple_des_cbc` falls back to a single DES cipher.

* Python 2 is no longer supported and `python_requires` is corrected to
  `>=3.8`, which is what the code has actually needed. The trove
  classifiers, the CI matrix and the documentation are updated to match.

* Security: The MAC of a DES secure messaging packet was only verified
  by its leading length and command code byte. The remaining six bytes
  of the recovered pre-image are now verified as well, which restores
  the forgery resistance from 16 to 64 bit. MAC tags and authentication
  challenges are compared in constant time.

* Bugfix: The DES secure `write` command rejected every response. A DES
  secure response is CBC encrypted and therefore padded to a multiple of
  8 byte, but the decrypted status flags were required to be exactly 2
  byte. This also affected `change_keys`, which writes through the same
  command.

* The list arguments of the FeliCa Standard commands are checked against
  the limits of the specification before a command frame is built.

* A command packet is rejected when it would exceed the 255 byte that
  the one byte data length field can announce. A wrapped around length
  byte would have put a frame on the air that no card can answer. The
  block count of a read is checked against what a single response packet
  holds, which is 15 blocks for Read Without Encryption and Read v2 and
  14 for the DES Read, because a read is bounded by its response while
  its command stays small.

* Bugfix: Status flag 2 no longer overrules status flag 1. Status flag 1
  is the sole authority on whether a command completed, and a non-zero
  status flag 2 alongside a normal completion is logged as a warning.
  The memory rewrite count warning `0x71` is raised after the write has
  been performed and some products pair it with status flag 1 `0x00`, so
  `write`, `write_v2`, `set_parameter`, `reset_mode`, `register_area`
  and `change_system_block` reported a completed command as a failure.

* `change_keys` now takes the `node` whose key it replaces in each
  entry, and resolves it to a position in the node list the session was
  authenticated against. Previously every key change addressed the first
  node of that list, so changing the key of any other node silently
  rewrote the wrong node's key. A node the session does not cover raises
  `ValueError`.

* An `AuthenticatedContext` records the node list its session was opened
  against, since a block list element names its target by position in
  that list.

* Security: Session keys no longer reach a log. The secure session
  credentials and the authenticated context print the length of a key
  instead of its bytes, and the nonces, challenges and derived keys of
  both mutual authentications are overwritten once the session holds
  them. `clear_authenticated_context` overwrites the session keys before
  dropping the context.

* The FeliCa card start-up time before the first polling command is
  raised from 5 ms to the recommended 20.4 ms. A card needs up to 20 ms
  from entering the field to being able to receive a command, so a
  reader that polls once could miss it.

* A new documentation chapter describes the FeliCa Standard commands,
  key derivation, secure messaging and issuance.

1.0.4 (2022-03-10)
------------------

* Bugfix: In Type 4 Tag communication the ISO-DEP MIU must be 2 octets less
  accomodate the EDC field that gets added by the reader device.

* Bugfix: Add trailing APDU LE byte when sending the application identifier
  during Type 4 Tag initialization. Code contributed by @kieran-mackey.

* Bugfix: Correct acquisition of Windows output stream handle for colorized
  terminal messages in example scripts. Code contributed by @mizutoki79.

1.0.3 (2019-07-27)
------------------

* Correct the IO handling of binary file input in `tagtool.py` when doing
  tag emulation. This wasn't properly tested for the 1.0.2 release.

* Use the correct name of `_get_osfhandle` Windows function for color output
  stream handler in command line interface helper module.

1.0.2 (2019-07-24)
------------------

* Bugfix: In tagtool.py the NDEF message input file for tag emulation must
  be opened in binary mode. Also reading from stdin must use the TextIO
  buffer attribute to get binary data.

1.0.1 (2019-06-07)
------------------

* Correct a missing Python3 related use of bytes instead of str when
  determing hexadecimal log output formatting.

* Use Sphinx 1.x compatible config file to get documentation built on
  ReadTheDocs.

1.0.0 (2019-06-06)
------------------

This is a major major release that brings Python3 compatibility but
also API changes that may break existing applications. Many thanks to
@mofe23 and @msnoigrs for their Python3 compatibility patches.

* The `nfc.ndef` package is removed. All NDEF decoding and encoding
  now uses the https://github.com/nfcpy/ndeflib library.

* The `nfc.snep.SnepClient.put` is removed. Application code must use
  either `put_records` or `put_octets`.

* The `nfc.snep.SnepClient.get` is removed. Application code must use
  either `get_records` or `get_octets`.

* The `nfc.snep.SnepServer.put` method changed to `process_put_request`
  and receives the ndef_message as a list of `ndef.Record` objects.

* The `nfc.snep.SnepServer.get` method changed to `process_get_request`
  and receives the ndef_message as a list of `ndef.Record` objects.
  The `acceptable_length` parameter is now handled by the SnepServer.

* The `nfc.handover.HandoverClient.send` method has changed to
  `send_records` and expects a list of `ndef.Record` objects. The new
  `send_octets` method allows to send a pre-encoded handover message.

* The `nfc.handover.HandoverClient.recv` method has changed to
  `recv_records` and returns a list of `ndef.Record` objects. The new
  `recv_octets` method returns the received encoded handover message.

* The `nfc.tag.Tag.NDEF.message` is removed. Application code must use
  `records` or `octets`.

* The `examples/ndeftool.py` script is removed. Similar functionality
  is provided by the https://github.com/nfcpy/ndeftool application.

0.13.6 (2019-06-05)
-------------------

* Corrections to LLCP SEC module:
  - fixed a bug in encrypt_update
  - explicitly load libcrypto 1.0

* Variable name fix in examples/beam.py by @turbolocust

* Python3 compatibility contribution by @henrycjc.

0.13.5 (2018-05-19)
-------------------

* Raise TagCommandError when NDEF data could not be written to the
  tag. Previously this was captured within the tag memory cache for
  Type1Tag and Type2Tag and only raised as IndexError.

* Improved and corrected documentation for libusb Windows DLL
  installation (thanks to @ghxbob for PR #95 and @henrycjc for PR
  #112).

* Identify Raspberry Pi via device tree model file (instead of
  /proc/cpuinfo).

* Allow debug logs with `python -m nfc -verbose` to ease bug reporting
  when reader enumeration fails.

0.13.4 (2017-11-10)
-------------------

* Raise nfc.tag.TagCommandError when NDEF data could not be written to
  the tag. Previously this was captured within the tag memory cache
  for Type1Tag and Type2Tag and raised as IndexError.

0.13.3 (2017-11-02)
-------------------

* Corrects a documentation error about the errors parameter that is
  not used for ndeflib.message_decoder() as wrongly stated in a docstr
  embedded code example.

0.13.2 (2017-07-12)
-------------------

* Fixes issue #73 "Importing termios prevents operation on Windows" by
  catching the import error that occurs when running on a non-posix
  system.

0.13.1 (2017-07-01)
-------------------

* Restructured serial device discovery to find USB serial device nodes
  on Mac OS X.

* Increased regression test coverage.

0.13.0 (2017-03-27)
-------------------

* This is a maintenance release to further replace the ndef submodule
  with ndeflib, now used by a couple of documentation examples
  verified with doctest.

* Part of this release is a large number of regression tests run with
  pytest. Some minor source code changes are the result of testing and
  preparative work towards future Python 3 compatibility.

0.12.0 (2017-01-04)
-------------------

* Release 0.12 marks the end of code-transfer from Launchpad to Github
  (and bazaar to git). The Launchpad site will stay for questions and
  answers.

* Release 0.12 also marks the begin of some code separation, starting
  with inclusion of the separate NDEF decoder/encoder module from
  https://github.com/nfcpy/ndeflib when installing from PyPI or
  running `setup.py`. The `Tag.ndef` attribute's new `records` member
  uses the new ndeflib for decode and encode.

* New module main function for "python -m nfc" searches for locally
  connected contactless devices and provides diagnostic output for
  some known issues with access rights and conflicting drivers.

* New `iterations` and `interval` options allow more fine tuning of
  the polling loop in `ContactlessFrontend.connect()`.

* New `beep-on-connect` option and implementation to let an ACR-122
  blink and sound when a card is detected. Contributed by
  https://github.com/svvitale

* Ability to apply factory format completely empty NTAG tags.

* Correct dump of FeliCa Mobile data structures and timeout tuning for
  some older FeliCa cards.

* A fix for the Raspberry Pi's erratic USB implementation, see
  https://github.com/nfcpy/nfcpy/wiki/USB-TTL-serial-adapter-on-Raspberry-Pi

* A number of bug fixes, source code and documentation improvements
  including contributions by GitHub members https://github.com/pyrog,
  https://github.com/Skylled and https://github.com/hideo54.

0.11.1 (2016-04-29)
-------------------

* Fixes an error in in the authentication procedure for Ultralight-C
  and NTAG21x Type 2 Tags.

0.11.0 (2016-04-21)
-------------------

* The main new feature of release 0.11 is the support for encrypted
  LLCP connections from the NFC Forum LLCP 1.3 Specification. The
  feature is available for Linux systems with OpenSSL crypto library
  (probably all). Encryption is automatically used if the supported by
  the peer device.

* The Python USB library has changed from PyUSB to the libusb1
  module (pip install libusb1). This allows to wait for a USB
  response packet and still being able to cancel with keyboard
  interrupt (which PyUSB was unfortunately blocking).

* Starting with this release the nfcpy library part (the nfc module
  but not the examples) will be uploaded to the Python Package Index
  for simple installation with 'pip install nfcpy'.
  
* The Type 2 Tag sector_select command could finally be tested with an
  NTAG I2C Tag and is now working as intended.

0.10.2 (2015-10-02)
-------------------

* Fixes an initialization issue when PN532 is connected to serial port
  on Raspberry Pi.

0.10.1 (2015-09-28)
-------------------

* Issue warning when nfc/clf/pn53x.py is atttempted to be used as a
  driver (since version 0.10 pn53x contains only an abstract base
  class, drivers are in pn531.py/pn532.py/pn533.py).

* Fixed an issue with PN532 deactivation - the chip needs additional
  time after change of serial baudrate before the next command may be
  send.

0.10.0 (2015-07-27)
-------------------

* Complete update of the tag read/write implementation to support
  features of specific tag products, such as password protection for
  Sony FeliCa Lite-S and NXP NTAG.

* Type 4B Tags (ISO Tags) are now supported. This completes support
  for all NFC Forum Tag Types.

* All contactless driver implementation is updated for generally more
  stability and an improved low-level API. The contactless frontend
  interface class and all ddrivers are now in one sub-package and emit
  debug messages with the logger "nfc.clf".

* The TTA/TTB/TTF/DEP communication types are replaced by RemoteTarget
  and LocalTarget types with enclosed communication parameters that
  allow more control of the discovery process. This change is only
  relevant for application code that has set specifc poll targets or
  implemented card emulation code, otherwise it won't be noticed.

* The contactless frontend connect() method understands some more
  options for callbacks and peer to peer communication settings.

* Serial (tty) readers can be automatically discovered by probing
  ports and drivers. On Linux, the maximum serial baudrate is checked
  and configured up to 921.6 kbaud (with a PN532). Note that automatic
  port and driver discovery may disturb other serial devices and
  should only be used if that is not a concern.
  
* New example tools use use the low-level driver API for very specific
  tasks like pure remote target discovery (with the option to do this
  repeatedly), listen to become discovered, and to simply observe when
  an external RF field is switched on and off (requires a PN531/2/3).

* The tagtool.py and beam.py tools can inspect frequently encountered
  permission problems and output targeted recommendations for solving
  them.

* Among other updates the documentation now gives more info about
  device capabilities on both the overview page as well as in the
  drivers section.

0.9.2 (2015-02-03)
------------------

* Fixes bug lp:1274973 "acr122 driver throws exception on frame length check"

0.9.1 (2014-02-13)
------------------

* Fixes bug lp:1279271 "error reading type 1 tag with more than 120 bytes"

0.9.0 (2014-01-31)
------------------

* First versioned release


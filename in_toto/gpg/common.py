"""
<Module Name>
  common.py

<Author>
  Santiago Torres-Arias <santiago@nyu.edu>

<Started>
  Nov 15, 2017

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Provides algorithm-agnostic gpg public key and signature parsing functions.
  The functions select the appropriate functions for each algorithm and
  call them.

"""
import struct
import binascii
import logging

import in_toto.gpg.util
from in_toto.gpg.exceptions import (PacketVersionNotSupportedError,
    SignatureAlgorithmNotSupportedError, KeyNotFoundError, KeyIdNotFoundError)
from in_toto.gpg.constants import (PACKET_TYPES,
        SUPPORTED_PUBKEY_PACKET_VERSIONS, SIGNATURE_TYPE_BINARY,
        SIGNATURE_TYPES_SELF,
        SUPPORTED_SIGNATURE_PACKET_VERSIONS, SUPPORTED_SIGNATURE_ALGORITHMS,
        SIGNATURE_HANDLERS, FULL_KEYID_SUBPACKET,
        PARTIAL_KEYID_SUBPACKET, SHA1, SHA256, SHA512)

from in_toto.gpg.formats import GPG_HASH_ALGORITHM_STRING

# Inherits from in_toto base logger (c.f. in_toto.log)
log = logging.getLogger(__name__)


def parse_pubkey_payload(data):
  """
  <Purpose>
    Parse the passed public-key packet (payload only) and construct a
    public key dictionary.

  <Arguments>
    data:
          An RFC4880 public key packet payload as described in section 5.5.2.
          (version 4) of the RFC.

          NOTE: The payload can be parsed from a full key packet (header +
          payload) by using in_toto.gpg.util.parse_packet_header.

          WARNING: this doesn't support armored pubkey packets, so use with
          care. pubkey packets are a little bit more complicated than the
          signature ones

  <Exceptions>
    ValueError
          If the passed public key data is empty.

    in_toto.gpg.exceptions.PacketVersionNotSupportedError
          If the packet version does not match
          in_toto.gpg.constants.SUPPORTED_PUBKEY_PACKET_VERSIONS

    in_toto.gpg.exceptions.SignatureAlgorithmNotSupportedError
          If the signature algorithm does not match one of
          in_toto.gpg.constants.SUPPORTED_SIGNATURE_ALGORITHMS

  <Side Effects>
    None.

  <Returns>
    A public key in the format in_toto.gpg.formats.PUBKEY_SCHEMA

  """
  if not data:
    raise ValueError("Could not parse empty pubkey payload.")

  ptr = 0
  keyinfo = {}
  version_number = data[ptr]
  ptr += 1
  if version_number not in SUPPORTED_PUBKEY_PACKET_VERSIONS: # pragma: no cover
    raise PacketVersionNotSupportedError(
        "Pubkey packet version '{}' not supported, must be one of {}".format(
          version_number, SUPPORTED_PUBKEY_PACKET_VERSIONS))

  # NOTE: Uncomment this line to decode the time of creation
  # time_of_creation = struct.unpack(">I", data[ptr:ptr + 4])
  ptr += 4

  algorithm = data[ptr]

  ptr += 1

  # TODO: Should we only export keys with signing capabilities?
  # Section 5.5.2 of RFC4880 describes a public-key algorithm octet with one
  # of the values described in section 9.1 that could be used to determine the
  # capabilities. However, in case of RSA subkeys this field doesn't seem to
  # correctly encode the capabilities. It always has the value 1, i.e.
  # RSA (Encrypt or Sign).
  # For RSA public keys we would have to parse the subkey's signature created
  # with the master key, for the signature's key flags subpacket, identified
  # by the value 27 (see section 5.2.3.1.) containing a list of binary flags
  # as described in section 5.2.3.21.
  if algorithm not in SUPPORTED_SIGNATURE_ALGORITHMS:
    raise SignatureAlgorithmNotSupportedError("Signature algorithm '{}' is not supported, please"
        " verify that your gpg configuration is creating either DSA or RSA"
        " signatures (see RFC4880 9.1. Public-Key Algorithms).".format(
          algorithm))
  else:
    keyinfo['type'] = SUPPORTED_SIGNATURE_ALGORITHMS[algorithm]['type']
    keyinfo['method'] = SUPPORTED_SIGNATURE_ALGORITHMS[algorithm]['method']
    handler = SIGNATURE_HANDLERS[keyinfo['type']]

  keyinfo['keyid'] = in_toto.gpg.util.compute_keyid(data)
  key_params = handler.get_pubkey_params(data[ptr:])

  return {
    "method": keyinfo['method'],
    "type": keyinfo['type'],
    "hashes": [GPG_HASH_ALGORITHM_STRING],
    "keyid": keyinfo['keyid'],
    "keyval" : {
      "private": "",
      "public": key_params
      }
    }


def parse_pubkey_bundle(data, keyid):
  """
  <Purpose>
    Parse the public key data received by GPG_EXPORT_PUBKEY_COMMAND and
    construct a public key dictionary, containing a master key and optional
    subkeys, where either the master key or the subkeys are identified by
    the passed keyid.

    NOTE: If the keyid matches one of the subkeys, a warning is issued to
    notify the user about potential privilege escalation.

  <Arguments>
    data:
          Public key data as written to stdout by GPG_EXPORT_PUBKEY_COMMAND.

  <Exceptions>
    ValueError:
          If no data is passed

    in_toto.gpg.exceptions.KeyNotFoundError
          If neither the master key or one of the subkeys match the passed
          keyid.

  <Side Effects>
    None.

  <Returns>
    A public key in the format in_toto.gpg.formats.PUBKEY_SCHEMA containing
    available subkeys, where either the master key or one of the subkeys match
    the passed keyid.

  """
  master_public_key = None
  sub_public_keys = {}

  full_master_key_packet = None
  last_full_user_id_packet = None
  last_full_sub_key_packet = None
  last_sub_key_payload = None

  # Iterate over the passed public key data and parse out master and sub keys.
  # The individual keys' headers identify the key as master or sub key.
  packet_start = 0
  while packet_start < len(data):
    # print("looping")
    payload, length, _type = in_toto.gpg.util.parse_packet_header(
        data[packet_start:])

    full_packet = data[packet_start:packet_start+length]

    try:
      # FIXME: Check below if we indeed got a main key as expected here
      if _type == PACKET_TYPES["master_pubkey_packet"]:
        master_public_key = parse_pubkey_payload(payload)
        full_master_key_packet = full_packet

      # FIXME: Check below if we indeed got a sub key as expected here
      elif _type == PACKET_TYPES["pub_subkey_packet"]:
        last_full_sub_key_packet = full_packet
        last_sub_key_payload = payload

      elif _type == PACKET_TYPES["user_id_packet"]:
        last_full_user_id_packet = full_packet

      elif _type == PACKET_TYPES["signature_packet"]:
        pass
        sig = parse_signature_packet(
            data[packet_start:], include_info=True,
            supported_signature_types=set(SIGNATURE_TYPES_SELF.values()),
            supported_hash_algorithms={SHA1, SHA256, SHA512})

        # if not (master_public_key["keyid"] == sig[keyid] or
        #     master_public_key["keyid"].endswith(sig["short_keyid"])):
        #   log.debug()


        sig["keyid"] = master_public_key["keyid"]
        del sig["short_keyid"]

        if sig["info"]["signature_type"] in {
            SIGNATURE_TYPES_SELF["cert_generic"],
            SIGNATURE_TYPES_SELF["cert_persona"],
            SIGNATURE_TYPES_SELF["cert_casual"],
            SIGNATURE_TYPES_SELF["cert_positive"]}:

          # FIXME: Is \x00\x00\x00 padding always necessary?
          content = (full_master_key_packet + b"\xb4\x00\x00\x00" +
              last_full_user_id_packet[1:])

          if SIGNATURE_HANDLERS[master_public_key["type"]].gpg_verify_signature(sig, master_public_key,
              content, hash_algorithm=sig["info"]["hash_algorithm"]):
            # TODO: parse info such as expiration date
            # only use expiration date for main key
            pass


        elif sig["info"]["signature_type"] == SIGNATURE_TYPES_SELF["subkey_binding"]:
          content = (full_master_key_packet + b"\x99" +
              last_full_sub_key_packet[1:])

          if SIGNATURE_HANDLERS[master_public_key["type"]].gpg_verify_signature(sig, master_public_key,
              content, hash_algorithm=sig["info"]["hash_algorithm"]):
            # We only add subkeys for which we have a valid subkey binding
            sub_public_key = parse_pubkey_payload(last_sub_key_payload)
            sub_public_keys[sub_public_key["keyid"]] = sub_public_key

            # TODO: parse info such as expiration date
            # only use expiration date for sub key

        else:
          log.debug("Ignoring gpg self-signature type '{}', we only handle"
              " types '{}' (see RFC4880 5.2.1. Signature Types).".format(_type,
              list(SIGNATURE_TYPES_SELF.values())))

          print("ignore signature")

      else:
        log.info("Ignoring gpg key packet '{}', we only handle packets '{}'"
            " (see RFC4880 4.3. Packet Tags).".format(_type,
              list(PACKET_TYPES.values())))
        # print("ignore packet")
        # if _type == 15 or _type == 0:
          # print("packet tag", _type, master_public_key["keyid"])


    # The data might contain non-supported subkeys, which we just ignore
    except (ValueError, PacketVersionNotSupportedError,
        SignatureAlgorithmNotSupportedError) as e:
      log.debug("In parse_pubkey_bundle: " + str(e))

    except KeyIdNotFoundError as e:
      print("KeyIdNotFoundError for " + master_public_key["keyid"])

    packet_start += length


  # 12.1.  Key Structures
  # ....
  # Primary-Key
  #   [Revocation Self Signature]
  #   [Direct Key Signature...]
  #    User ID [Signature ...]
  #   [User ID [Signature ...] ...]
  #   [User Attribute [Signature ...] ...]
  #   [[Subkey [Binding-Signature-Revocation]
  #           Primary-Key-Binding-Signature] ...]

  # A subkey always has a single signature after it that is issued using
  # the primary key to tie the two keys together.

   # 5.2.3.3.  Notes on Self-Signatures
   # A self-signature is a binding signature made by the key to which the
   # signature refers.  There are three types of self-signatures, the
   # certification signatures (types 0x10-0x13), the direct-key signature
   # (type 0x1F), and the subkey binding signature (type 0x18).  For
   # certification self-signatures, each User ID may have a self-
   # signature, and thus different subpackets in those self-signatures.
   # For subkey binding signatures, each subkey in fact has a self-
   # signature.  Subpackets that appear in a certification self-signature
   # apply to the user name, and subpackets that appear in the subkey
   # self-signature apply to the subkey.  Lastly, subpackets on the
   # direct-key signature apply to the entire key.


  # ...
  # An implementation that encounters multiple self-signatures on the
  # same object may resolve the ambiguity in any way it sees fit, but it
  # is RECOMMENDED that priority be given to the most recent self-
  # signature.



  # Since GPG returns all pubkeys associated with a keyid (master key and
  # subkeys) we check which key matches the passed keyid.
  # If the matching key is a subkey, we warn the user because we return
  # the whole bundle (master plus all subkeys) and not only the subkey.
  # If no matching key is found we raise a KeyNotFoundError.
  for idx, public_key in enumerate(
      [master_public_key] + list(sub_public_keys.values())):
    if public_key and public_key["keyid"].endswith(keyid.lower()):
      if idx > 1:
        log.warning("Exporting master key '{}' including subkeys '{}' for"
            " passed keyid '{}'.".format(master_public_key["keyid"],
            ", ".join(list(sub_public_keys.keys())), keyid))
      break

  else:
    raise KeyNotFoundError("No key found for gpg keyid '{}'".format(keyid))

  # Add subkeys dictionary to master pubkey "subkeys" field if subkeys exist
  if sub_public_keys:
    master_public_key["subkeys"] = sub_public_keys

  return master_public_key


def parse_signature_packet(data, supported_signature_types=None,
    supported_hash_algorithms=None, include_info=False):
  """
  <Purpose>
    Parse the signature information on an RFC4880-encoded binary signature data
    buffer.

    NOTE: Older gpg versions (< FULLY_SUPPORTED_MIN_VERSION) might only
    reveal the partial key id. It is the callers responsibility to determine
    the full keyid based on the partial keyid, e.g. by exporting the related
    public and replacing the partial keyid with the full keyid.

  <Arguments>
    data:
           the RFC4880-encoded binary signature data buffer as described in
           section 5.2 (and 5.2.3.1).

  <Exceptions>
    ValueError: if the signature packet is not supported or the data is
      malformed

  <Side Effects>
    None.

  <Returns>
    A signature dictionary matching in_toto.gpg.formats.SIGNATURE_SCHEMA

  """
  if not supported_signature_types:
    supported_signature_types = {SIGNATURE_TYPE_BINARY}

  if not supported_hash_algorithms:
    supported_hash_algorithms = {SHA256}

  data, junk_length, junk_type = in_toto.gpg.util.parse_packet_header(
      data, PACKET_TYPES['signature_packet'])

  ptr = 0

  # we get the version number, which we also expect to be v4, or we bail
  # FIXME: support v3 type signatures (which I haven't seen in the wild)
  version_number = data[ptr]
  ptr += 1
  if version_number not in SUPPORTED_SIGNATURE_PACKET_VERSIONS: # pragma: no cover
    raise ValueError("Signature version '{}' not supported, must be one of"
      " {}.".format(version_number, SUPPORTED_SIGNATURE_PACKET_VERSIONS))

  # here, we want to make sure the signature type is indeed PKCSV1.5 with RSA
  signature_type = data[ptr]
  ptr += 1

  if signature_type not in supported_signature_types: # pragma: no cover
    raise ValueError("Signature type '{}' not supported, must be one of {}"
      " (see RFC4880 5.2.1. Signature Types).".format(signature_type,
      supported_signature_types))

  signature_algorithm = data[ptr]
  ptr += 1

  if signature_algorithm not in SUPPORTED_SIGNATURE_ALGORITHMS: # pragma: no cover
    raise SignatureAlgorithmNotSupportedError("Signature algorithm '{}' is not supported, please"
        " verify that your gpg configuration is creating either DSA or RSA"
        " signatures (see RFC4880 9.1. Public-Key Algorithms).".format(
          signature_algorithm))

  key_type = SUPPORTED_SIGNATURE_ALGORITHMS[signature_algorithm]['type']
  handler = SIGNATURE_HANDLERS[key_type]

  hash_algorithm = data[ptr]
  ptr += 1

  if hash_algorithm not in supported_hash_algorithms: # pragma: no cover
    raise ValueError("Hash algorithm '{}' not supported, must be one of {}"
        " (see RFC4880 9.4. Hash Algorithms).".format(hash_algorithm,
        supported_hash_algorithms))

  # Obtain the hashed octets
  hashed_octet_count = struct.unpack(">H", data[ptr:ptr+2])[0]
  ptr += 2
  hashed_subpackets = data[ptr:ptr+hashed_octet_count]
  hashed_subpacket_info = in_toto.gpg.util.parse_subpackets(hashed_subpackets)

  # Check whether we were actually able to read this much hashed octets
  if len(hashed_subpackets) != hashed_octet_count: # pragma: no cover
    raise ValueError("This signature packet seems to be corrupted."
        "It is missing hashed octets!")

  ptr += hashed_octet_count
  other_headers_ptr = ptr

  unhashed_octet_count = struct.unpack(">H", data[ptr: ptr + 2])[0]
  ptr += 2

  unhashed_subpackets = data[ptr:ptr+unhashed_octet_count]
  unhashed_subpacket_info = in_toto.gpg.util.parse_subpackets(
      unhashed_subpackets)

  ptr += unhashed_octet_count

  info = {
    "signature_type": signature_type,
    "hash_algorithm": hash_algorithm,
    "subpackets": [],
  }

  keyid = ""
  short_keyid = ""

  # Parse Issuer (short keyid) and Issuer Fingerprint (full keyid) from hashed
  # and unhashed signature subpackets. Full keyids are only available in newer
  # signatures. (see RFC4880 and rfc4880bis-06 5.2.3.1.)
  # NOTE: A subpacket may be found either in the hashed or unhashed subpacket
  # sections of a signature. If a subpacket is not hashed, then the information
  # in it cannot be considered definitive because it is not part of the
  # signature proper.
  # (see RFC4880 5.2.3.2.)
  # NOTE: Signatures may contain conflicting information in subpackets. In most
  # cases, an implementation SHOULD use the last subpacket, but MAY use any
  # conflict resolution scheme that makes more sense.
  # (see RFC4880 5.2.4.1.)
  # Below we only consider the last and favor hashed over unhashed subpackets
  for subpacket_type, subpacket_data in \
      unhashed_subpacket_info + hashed_subpacket_info:
    if subpacket_type == FULL_KEYID_SUBPACKET:
      # NOTE: The first byte of the subpacket payload is a version number
      # (see rfc4880bis-06 5.2.3.28.)
      keyid = binascii.hexlify(subpacket_data[1:]).decode("ascii")

    # We also return the short keyid, because the full might not be available
    if subpacket_type == PARTIAL_KEYID_SUBPACKET:
      short_keyid = binascii.hexlify(subpacket_data).decode("ascii")

    info["subpackets"].append((
      subpacket_type,
      binascii.hexlify(subpacket_data).decode("ascii"),
      subpacket_map.get(subpacket_type)))


  # Fail if there is no keyid at all (this should not happen)
  if not (keyid or short_keyid): # pragma: no cover
    raise ValueError("This signature packet seems to be corrupted. It does "
        "not have an 'Issuer' or 'Issuer Fingerprint' subpacket (see RFC4880 "
        "and rfc4880bis-06 5.2.3.1. Signature Subpacket Specification).")

  # Fail keyid and short keyid are specified but don't match
  if keyid and not keyid.endswith(short_keyid): # pragma: no cover
    raise ValueError("This signature packet seems to be corrupted. The key ID "
        "'{}' of the 'Issuer' subpacket must match the lower 64 bits of the "
        "fingerprint '{}' of the 'Issuer Fingerprint' subpacket (see RFC4880 "
        "and rfc4880bis-06 5.2.3.28. Issuer Fingerprint).".format(
        short_keyid, keyid))

  # Uncomment this variable to obtain the left-hash-bits information (used for
  # early rejection)
  #left_hash_bits = struct.unpack(">H", data[ptr:ptr+2])[0]
  ptr += 2

  signature = handler.get_signature_params(data[ptr:])

  signature_data = {
    'keyid': "{}".format(keyid),
    'short_keyid': "{}".format(short_keyid),
    'other_headers': binascii.hexlify(data[:other_headers_ptr]).decode('ascii'),
    'signature': binascii.hexlify(signature).decode('ascii')
  }

  if include_info:
    signature_data["info"] = info

  return signature_data




subpacket_map = {
  0x00: "Reserved",
  0x01: "Reserved",
  0x02: "Signature Creation Time",
  0x03: "Signature Expiration Time",
  0x04: "Exportable Certification",
  0x05: "Trust Signature",
  0x06: "Regular Expression",
  0x07: "Revocable",
  0x08: "Reserved",
  0x09: "Key Expiration Time",
  0x0a: "Placeholder for backward compatibility",
  0x0b: "Preferred Symmetric Algorithms",
  0x0c: "Revocation Key",
  0x0d: "Reserved",
  0x0e: "Reserved",
  0x0f: "Reserved",
  0x10: "Issuer",
  0x11: "Reserved",
  0x12: "Reserved",
  0x13: "Reserved",
  0x14: "Notation Data",
  0x15: "Preferred Hash Algorithms",
  0x16: "Preferred Compression Algorithms",
  0x17: "Key Server Preferences",
  0x18: "Preferred Key Server",
  0x19: "Primary User ID",
  0x1a: "Policy URI",
  0x1b: "Key Flags",
  0x1c: "Signer's User ID",
  0x1d: "Reason for Revocation",
  0x1e: "Features",
  0x1f: "Signature Target",
  0x20: "Embedded Signature"
}
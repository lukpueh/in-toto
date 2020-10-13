from securesystemslib.interface import (
    generate_and_write_rsa_keypair,
    import_rsa_privatekey_from_file,
    import_rsa_publickey_from_file,
    generate_and_write_ed25519_keypair,
    import_ed25519_publickey_from_file,
    import_ed25519_privatekey_from_file,
    generate_and_write_ecdsa_keypair,
    import_ecdsa_publickey_from_file,
    import_ecdsa_privatekey_from_file,
    import_privatekey_from_file,
    import_publickeys_from_file)

from securesystemslib.gpg.functions import (
    export_pubkey as import_gnupg_publickey,
    export_pubkeys as import_gnupg_publickeys)

KEY_TYPE_RSA = 'rsa'
KEY_TYPE_ED25519 = 'ed25519'
SUPPORTED_KEY_TYPES = [KEY_TYPE_ED25519, KEY_TYPE_RSA]
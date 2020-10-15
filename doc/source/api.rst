API
===

The in-toto API provides various functions and :doc:`classes <model>` that you can use
to generate, consume, modify and verify in-toto metadata, as a more
feature-rich, programmable alternative to the :doc:`command line tools <command-line-tools/index>`.


Evidence Generation
-------------------

.. autofunction:: in_toto.runlib.in_toto_run
.. autofunction:: in_toto.runlib.in_toto_record_start
.. autofunction:: in_toto.runlib.in_toto_record_stop


Supply Chain Verification
-------------------------

.. autofunction:: in_toto.verifylib.in_toto_verify

Utilities
---------

.. autofunction:: securesystemslib.interface.generate_and_write_rsa_keypair
.. autofunction:: securesystemslib.interface.import_rsa_privatekey_from_file
.. autofunction:: securesystemslib.interface.import_rsa_publickey_from_file
.. autofunction:: securesystemslib.interface.generate_and_write_ed25519_keypair
.. autofunction:: securesystemslib.interface.import_ed25519_publickey_from_file
.. autofunction:: securesystemslib.interface.import_ed25519_privatekey_from_file
.. autofunction:: securesystemslib.interface.generate_and_write_ecdsa_keypair
.. autofunction:: securesystemslib.interface.import_ecdsa_publickey_from_file
.. autofunction:: securesystemslib.interface.import_ecdsa_privatekey_from_file
.. autofunction:: securesystemslib.interface.import_publickeys_from_file
.. autofunction:: securesystemslib.interface.import_privatekey_from_file
.. autofunction:: securesystemslib.gpg.functions.export_pubkey
.. autofunction:: securesystemslib.gpg.functions.export_pubkeys

.. _changelog:

Changelog
=========
* 1.0.1

    - Initial Release.

* 1.0.2

    - Improvement of the :term:`Black List` handling.

* 1.0.3

    - Improvement of the :term:`Black List` handling with database changes.
      NOTE: When upgrading from 1.0.1 or 1.0.2 to 1.0.3 or later, you must execute the database migration application (see :ref:`database_migration`).
    - Introduction of the configuration wizard.
    - Improvements for Docker integration.
    - Various bug fixes.

* 1.0.4

    - Add the eIDAS SAML Demo.
    - Fix ID generation and audience restriction in the eIDAS SAML response.
    - Fix for the eIDAS Middleware Docker integration.
    - Fix the project setup of the password generator.
    - Older databases are now also supported in the database migration tool.
    - Other minor fixes and improvements.

* 1.0.5

    - eIDAS Middleware: Fix wrong certificate in the metadata for the encryption part.
    - eIDAS Middleware: The URL for the entityID in the metadata must now be set in the configuration. Add SERVER_URL=https://host:port to eidasmiddleware.properties.
    - Configuration Wizard: Adapt for new configuration value. Use the value from the eID configuration page.
    - Configuration Wizard: Ensure that only one connector metadata file is saved.
    - Configuration Wizard: Ensure that the original filenames are used when loading and saving a previous configuration.

* 1.0.6

    - eIDAS Middleware: Fix bug introduced with version 1.0.5 where two URLs in the SAML response were switched.
    - eIDAS Middleware: Improve logging in case of unparsable authentication request.

* 1.0.7

    **Security Advisory**

    There were two security issues reported to the German POSC and Governikus. This release fixes these issues.
    It is strongly recommended to immediately update to this release as the XXE attack allows an unauthenticated remote attacker to read ASCII files from the file system which can be read by the Middleware Java process.

    - eIDAS Middleware: **Security Fix** Endpoints that parse XML content like ``/RequestReceiver`` or ``/paosreceiver`` were vulnerable to XXE attacks. These endpoints are no longer vulnerable against XXE attacks.
    - eIDAS Middleware: **Security Fix** The ``/TcToken`` endpoint was vulnerable against XXS attacks as requests parameters were inserted in the HTML response. All endpoints that display HTML content no longer insert user input into the HTML content.
    - eIDAS Middleware: The Master List Trust Anchor for the ``POSeIDAS_PRODUCTION.xml`` template is updated.

* 1.1.0

    - eIDAS Middleware: Support multiple metadata files as well as multiple :term:`eID Service Provider` s.
    - Configuration Wizard: Support multiple metadata files and multiple :term:`eID Service Provider` s.
    - eIDAS Middleware: Implement the recommendations from the latest pen test.
    - eIDAS Middleware: The admin interface can listen on a different port than the actual application endpoints. The admin interface is now available on a different context path, e.g. ``https://[host]:[port]/admin-interface/list``
    - eIDAS Middleware: New HTML designs for starting the AusweisApp2 and error messages.
    - eIDAS Middleware: A HSM Module can be used via the PKCS11 interface for different cryptographic actions.
    - Configuration Wizard: Support HSM configuration.
    - eIDAS Middleware: Fix padding and OID identifier in case ECDH encryption is used.
    - eIDAS Middleware: Add whitelist for allowed document signer types which can be extended using the configuration.
    - eIDAS Middleware: The validity of the metadata is now configurable, the default value is 30 days.

* 1.2.0

    - eIDAS Middleware: Fix handling of empty or absent RelayState.
    - eIDAS Middleware: Fix the order of attributes in the current address.
    - eIDAS Middleware: Fix some typos in the creation of SAML responses.
    - eIDAS Middleware: Remove the assertion in SAML responses when status is not success.
    - eIDAS Middleware: Remove carriage returns in the base64 representation of the SAML response.

    Note: The carriage returns inside the SAML response, e.g. in signatures and cipher texts, are not removed.
    These are created by OpenSAML / xmlsec following W3C XML signature and encryption specifications.


    Known Issue:
    The SUN PKCS11 security provider that is shipped with JAVA 8 does not support RSA-PSS signatures.
    In order to use a HSM module and stay in line with the eIDAS cryptographic requirements, the use of EC cryptography for the SAML signature is mandatory.
    This issue will be resolved when the eIDAS Middleware supports JAVA 11 as this version comes with a newer SUN PKCS11 security provider.

* 1.2.1
    - eIDAS Middleware: Fix SAML encryption with EC certificates.

* 1.2.2

    - eIDAS Middleware: Fix a bug where the newest generation of German eID cards were not accepted.

* 1.2.4

    - eIDAS Middleware: Security Patch

* 1.2.5

    - eIDAS Middleware: Change certificate chain building algorithm.
    - eIDAS Middleware: Update xmlsec and bouncycastle.

* 1.2.7

    - eIDAS Middleware: Fix Log4j security issue.

* 1.2.8

    - eIDAS Middleware: Update log4j to version 2.17.1.

* 1.2.9

    - eIDAS Middleware: Update third party libraries for security fixes.

* 1.2.10

    - eIDAS Middleware: Security patch.

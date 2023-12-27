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
  It is strongly recommended to immediately update to this release as the XXE attack allows an unauthenticated
  remote attacker to read ASCII files from the file system which can be read by the Middleware Java process.

    - eIDAS Middleware: **Security Fix** Endpoints that parse XML content like ``/RequestReceiver`` or ``/paosreceiver`` were vulnerable to XXE attacks. These endpoints are no longer vulnerable against XXE attacks.
    - eIDAS Middleware: **Security Fix** The ``/TcToken`` endpoint was vulnerable against XXS attacks as requests parameters were inserted in the HTML response. All endpoints that display HTML content no longer insert user input into the HTML content.
    - eIDAS Middleware: The Master List Trust Anchor for the ``POSeIDAS_PRODUCTION.xml`` template is updated.

* 1.1.0

    - eIDAS Middleware: Support multiple metadata files as well as multiple :term:`eID Service Providers<eID Service Provider>`.
    - Configuration Wizard: Support multiple metadata files and multiple :term:`eID Service Providers<eID Service Provider>`.
    - eIDAS Middleware: Implement the recommendations from the latest pen test.
    - eIDAS Middleware: The admin interface can listen on a different port than the actual application endpoints. The admin interface is now available on a different context path, e.g. ``https://[host]:[port]/admin-interface/list``
    - eIDAS Middleware: New HTML designs for starting the AusweisApp2 and error messages.
    - eIDAS Middleware: A HSM Module can be used via the PKCS11 interface for different cryptographic actions.
    - Configuration Wizard: Support HSM configuration.
    - eIDAS Middleware: Fix padding and OID identifier in case ECDH encryption is used.
    - eIDAS Middleware: Add whitelist for allowed document signer types which can be extended using the configuration.
    - eIDAS Middleware: The validity of the metadata is now configurable, the default value is 30 days.

* 1.1.1

    - eIDAS Middleware: Fix a bug where the newest generation of German eID cards were not accepted.

* 1.2.0

    - eIDAS Middleware: Fix handling of empty or absent RelayState.
    - eIDAS Middleware: Fix the order of attributes in the current address.
    - eIDAS Middleware: Fix some typos in the creation of SAML responses.
    - eIDAS Middleware: Remove the assertion in SAML responses when status is not success.
    - eIDAS Middleware: Remove carriage returns in the base64 representation of the SAML response.

  Note: The carriage returns inside the SAML response, e.g. in signatures and cipher texts, are not removed.
  These are created by OpenSAML / xmlsec following W3C XML signature and encryption specifications.

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

    - eIDAS Middleware: Security Patch

* 2.0.0

    - eIDAS Middleware: Support version 1.2 of the eIDAS specifications.
    - eIDAS Middleware: Add a CRL check to Passive Authentication.
    - eIDAS Middleware: There is no longer a dedicated Defect List trust anchor.
      Trust is instead established using the Master List.
    - Configuration Wizard: Remove option to configure Defect List trust anchor.
    - eIDAS Middleware: Perform some certificate checks on startup.
    - eIDAS Middleware: Option to have unsigned metadata, including download button in admin interface.
    - eIDAS Middleware: Overhaul admin interface.
    - eIDAS Middleware: Display status of AusweisApp2 on middleware landing page.
    - eIDAS Middleware: Load resources (css, js, ...) with context path.
    - eIDAS Middleware: Add support for a second test CA.
    - Configuration Wizard: Option to configure second test CA.

  Note: The new test CA is introduced to slowly replace the old one. Do not change CA settings on your own.
  The process of phasing out the old and migrating to the new will be initiated and guided by Governikus.

* 2.0.1

    - eIDAS Middleware: Fix a bug where the newest generation of German eID cards were not accepted.

* 2.1.0

    - eIDAS Middleware: The new eID card for citizens of the European Union and the European Economic Area is
      automatically accepted by default.
    - eIDAS Middleware: Support for :term:`Request Signer Certificates<Request Signer Certificate>`.
    - eIDAS Middleware: Replace the template-based SAML message generation with OpenSAML methods.
    - eIDAS Middleware: ProviderName is treated as optional in AuthnRequests, it is independent of the RequesterID.
    - eIDAS Middleware: NameIDPolicy is treated as optional in AuthnRequests, illegal values will be rejected.
    - eIDAS Middleware: SAML metadata and responses no longer include line breaks in <SignatureValue> or <CipherValue>.
    - eIDAS Middleware: SAML error responses will always contain one of the allowed top level SAML status codes. Sub
      status codes and status message contain more specific information.

* 2.2.1

    - eIDAS Middleware: Add test mode to get SAML responses without eID interaction.
    - eIDAS Middleware: Improve SNMP integration.
    - eIDAS Middleware: The information from the SNMP integration is also shown in the admin interface.
    - eIDAS Middleware: Add the 'method' attribute to the SubjectConfirmation element in the SAML assertion.
    - eIDAS Middleware: Use the proxy settings also for the connection check.
    - eIDAS Middleware: The javascript check to detect if the AusweisApp2 is running is disabled for Safari browsers as
      they block the javascript requests to the AusweisApp2.
    - eIDAS Middleware: Fix a bug introduced with 2.1.0 where the country identifier in the address would be placed in
      ``adminunitSecondLine``

* 2.2.2

    - eIDAS Middleware: Security Patch

* 2.2.3

    - eIDAS Middleware: Change certificate chain building algorithm.
    - eIDAS Middleware: Update xmlsec.
    - eIDAS Middleware: Improve stability in trust anchor management.

* 2.2.5

    - eIDAS Middleware: Fix Log4j security issue.

* 2.2.6

    - eIDAS Middleware: Update log4j to version 2.17.1.

* 2.2.7

    - eIDAS Middleware: Update eidas-opensaml to fix a bug with the CurrentAddress
      and update other third party libraries for security fixes.

  Known Issue for all versions before 3.0.0:
  The SUN PKCS11 security provider that is shipped with Java 8 does not support RSA-PSS signatures.
  In order to use an HSM and stay in line with the eIDAS cryptographic requirements,
  the use of EC cryptography for the SAML signature is mandatory.

* 2.2.8

    - eIDAS Middleware: Security Patch

* 3.0.0

    - All components: Now supporting Java 11. Support for Java 8 is discontinued.
    - eIDAS Middleware: With Java 11, the PKCS11 provider now supports RSA-PSS signatures.
    - eIDAS Middleware: Remove support of cryptographic algorithms not following eIDAS requirements
      which had been kept for the Java 8 SUN PKCS11 provider.
    - eIDAS Middleware: Remove support of older DVCA service versions, thus removing the need of different policies.
    - eIDAS Middleware: Restructure configuration.
    - eIDAS Middleware: Extend admin interface to be a configuration interface as well.
    - Configuration Migration: Add new component to facilitate migration from 2.x.
    - Remove configuration-wizard and password-generator. The functionality of these two artifacts is now
      implemented in the eIDAS Middleware.

* 3.0.1

    - eIDAS Middleware: Fix a bug where the wrong country code was published in the metadata.
    - eIDAS Middleware: All name identifiers are published in the metadata as required by eIDAS SAML Message Format
      1.2.
    - eIDAS Middleware: Update DVCA server certificate in eIDAS_Middleware_configuration_test.xml
    - Configuration Migration: Fix a bug that migrated the wrong URL for communication with the DVCA for production
      systems.


* 3.1.0

    - All components: Code cleanups.
    - eIDAS Middleware: Using identglue to check the availability of the AusweisApp2.
    - eIDAS Middleware: Added a timer to renew an expired CVC with a
      :term:`Request Signer Certificate<Request Signer Certificate>` when the current CVC is expired less than two days.
        - Added a notification in the Admin-UI to indicate that the renewal will be tried.
    - eIDAS Middleware: Fix unsuccessful indication of a public service provider on certain conditions.
    - eIDAS Middleware: Obsolete decryption key pair for SAML has been removed in the Admin-UI.
    - eIDAS Middleware: The used holder reference will be logged if an CVC request is unsuccessful.
    - eIDAS Middleware: A sequence number is never reused for CVC requests of a service provider.
    - eIDAS Demo: Improved design and added decrypted assertion on result page.
    - eIDAS Middleware: Added support for Brainpool elliptic curves on TLS connections.
    - eIDAS Middleware: Static resources have been moved from the base path to module specific paths.
    - eIDAS Middleware: SAML redirect binding has been added.
    - eIDAS Middleware: Added support for the natural person attribute 'Nationality'.

* 3.1.1

    - eIDAS Middleware: Update identglue and fix behaviour for mobile use.
    - eIDAS Middleware: Add the shibboleth repository to pom.xml

* 3.2.0

    - All components: Update to Java 17.
    - All components: Update to Spring Boot 3.1.
    - eIDAS Middleware: Fix use of P12 keystores for TLS keys.
    - eIDAS Middleware: Fix display of CVC availability on the status page.
    - eIDAS Middleware: Remove deprecated configuration parts in the documentation.
    - eIDAS Middleware: Only accept specified cryptographic algorithms and elliptic curve parameters.
    - eIDAS Middleware: Fix generation of sequence number after an initial CVC request.
    - eIDAS Middleware: Improve form validation for initial CVC request.
    - eIDAS Middleware & Demo: Update new references to the German eID client.

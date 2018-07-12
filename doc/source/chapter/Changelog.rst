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
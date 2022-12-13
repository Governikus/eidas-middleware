.. _configuration-mw:

Configuration of the eIDAS Middleware application
=================================================

Necessary keys and certificates
-------------------------------

In order to setup the middleware you will need to provide some key stores and certificates.
The following overview illustrates the required certificates and key stores.

.. image:: ../images/Certs_and_Interfaces.png


The following table describes the individual key stores and certificates:

.. table::
    :widths: 2 18 40 40

    +--------------------+---------------------------------------------------------------------------------------------+-----------------------------------------------------------------------------+
    | Name               | Description                                                                                 | Where to configure                                                          |
    +====================+=============================================================================================+=============================================================================+
    | Server TLS         | This key store is used to setup the HTTPS port of the server.                               | application.properties > server.ssl.key-store                               |
    | Key Store          |                                                                                             |                                                                             |
    +--------------------+---------------------------------------------------------------------------------------------+-----------------------------------------------------------------------------+
    | eIDAS Middleware   | This key store is used for the SAML communication with the eIDAS Connector.                 |                                                                             |
    | SAML Key Store     |                                                                                             |                                                                             |
    +--+-----------------+---------------------------------------------------------------------------------------------+-----------------------------------------------------------------------------+
    |  | SAML Signature  | This key store is used to sign the outgoing SAML responses.                                 | Admin-UI > eIDAS > Signature key pair                                       |
    |  | Key Store       |                                                                                             |                                                                             |
    |  |                 | In addition this key store is used to sign the SAML metadata of the eIDAS Middleware.       |                                                                             |
    |  |                 |                                                                                             |                                                                             |
    |  |                 | The corresponding certificate must be available to the remote party (eIDAS Connector)       |                                                                             |
    |  |                 | so that the SAML metadata can be verified.                                                  |                                                                             |
    +--+-----------------+---------------------------------------------------------------------------------------------+-----------------------------------------------------------------------------+
    |  | SAML Decryption | This key store is used to decrypt the incoming SAML requests.                               | Admin-UI > eIDAS > Decryption key pair                                      |
    |  | Key Store       |                                                                                             |                                                                             |
    +--+-----------------+---------------------------------------------------------------------------------------------+-----------------------------------------------------------------------------+
    | eIDAS Connector    | This key store is used for the SAML communication with the eIDAS-Middleware.                |                                                                             |
    | SAML Key Store     |                                                                                             |                                                                             |
    +--+-----------------+---------------------------------------------------------------------------------------------+-----------------------------------------------------------------------------+
    |  | SAML Signature  | This key store is used to sign the outgoing SAML requests.                                  | Admin-UI > Connector metadata > Metadata signature verification certificate |
    |  | Key Store       |                                                                                             |                                                                             |
    |  |                 | In addition this key store is used to sign the SAML metadata of the eIDAS Connector.        |                                                                             |
    |  |                 |                                                                                             |                                                                             |
    |  |                 | The corresponding certificate must be available to the remote party                         |                                                                             |
    |  |                 | (eIDAS Middleware) so that the SAML metadata can be verified.                               |                                                                             |
    +--+-----------------+---------------------------------------------------------------------------------------------+-----------------------------------------------------------------------------+
    |  | SAML Decryption | This key store is used to decrypt the incoming SAML responses                               |                                                                             |
    |  | Key Store       |                                                                                             |                                                                             |
    +--+-----------------+---------------------------------------------------------------------------------------------+-----------------------------------------------------------------------------+
    | BerCA Client       | This key store is needed to access the :term:`Authorization CA`.                            | Admin-UI > eID service provider > DVCA client authentication key pair       |
    | Key Store          |                                                                                             |                                                                             |
    +--------------------+---------------------------------------------------------------------------------------------+-----------------------------------------------------------------------------+
    | BerCA Server       | This certificate is needed to validate the BerCA server certificate of the                  | Admin-UI > DVCA > DVCA server certificate                                   |
    | Certificate        | :term:`Authorization CA`.                                                                   |                                                                             |
    +--------------------+---------------------------------------------------------------------------------------------+-----------------------------------------------------------------------------+
    | Master List        | This certificate is needed to verify the signature of the :term:`Master List`.              | Admin-UI > DVCA > Master List Trust Anchor                                  |
    | Trust Anchor       |                                                                                             |                                                                             |
    +--------------------+---------------------------------------------------------------------------------------------+-----------------------------------------------------------------------------+
    | Black List         | This certificate is needed to verify the signature of the :term:`Black List`.               | Admin-UI > DVCA > Black List Trust Anchor                                   |
    | Trust Anchor       |                                                                                             |                                                                             |
    +--------------------+---------------------------------------------------------------------------------------------+-----------------------------------------------------------------------------+


Please use only JKS or PKCS#12 key stores.

It is required to create the BerCA Client Key Store in consultation with the respective :term:`Authorization CA` as they
might have additional requirements for the key.
They will also provide you with their TLS server certificate which needs to be entered into the configuration as well.

Be advised that the Common Name or Subject Alternative Name of the TLS Certificate must match with the URL of the
middleware as it is reachable from the Internet.
This is important as the AusweisApp2 will check the URL in the authorization certificate against the URL that is
received from the eIDAS Middleware.
E.g., if the middleware is running on ``https://your.eidas.domain.eu/eidas-middleware/`` or
``https://your.eidas.domain.eu:8443/eidas-middleware/``, the CN or SAN of the TLS certificate must include
``your.eidas.domain.eu``.

For a test system, this TLS certificate may be self signed. However for a production system, this TLS certificate must
meet the requirements of the `eIDAS Crypto Requirements, section 2.4 <https://ec.europa.eu/digital-building-blocks/wikis/display/DIGITAL/eIDAS+eID+Profile?preview=/467109280/467109282/eIDAS%20Cryptographic%20Requirement%20v.1.2%20Final.pdf>`_
which states that qualified website certificates must be used.

For a successful connection of the eIDAS Middleware with your eIDAS Connector(s), their SAML Metadata must be exchanged.
The metadata of eIDAS Nodes contain the certificates that should be used for encryption and signature verification,
the URLs for receiving SAML requests and responses and other SAML and eIDAS related data.
While it is also possible to get the eIDAS Middleware's Metadata without a signature, you must use the certificate of
eIDAS Middleware SAML Signature Key Store to validate the eIDAS Middleware's Metadata.
Additionally, you must provide the certificate of the eIDAS Connector SAML Signature Key Store so that the Middleware can
validate your Connector's Metadata.


Setup the application.properties
--------------------------------

The ``application.properties`` file is the main configuration file for a Spring Boot application.
It must be setup prior to the first start of the application.

Adjust the template located in ``/opt/eidas-middleware/config``:
(If there is no template, copy the following one)

.. literalinclude:: application.properties

This configuration file contains the following sections:

#.  **server settings**

    You need to provide two ports on which the middleware will be accessed. The first (``server.port``) is the port
    for the eID functionality, the second (``server.adminInterfacePort``) facilitates access
    to the administration interface. Both ports must be given and must not contain the same value.
    The TLS settings are used for both ports, e.g. both ports use https or both ports use http.

    .. note::
        The eID port must be reachable by the users' eID clients from the internet while you can
        limit access to the second port to your administrators only.

#.  **TLS settings**

    To configure the TLS connection with your Server TLS Key Store, insert the appropriate values in this section.

    .. hint::
        If you change the TLS key store for the eIDAS Middleware, you must inform the :term:`Authorization CA`
        about the new TLS certificate. If you use a TLS key store that is not known to the :term:`Authorization CA`,
        the eIDAS Middleware may not work properly. If you change the TLS key store, please send an e-mail with the
        new TLS certificate and the CHR of your :term:`CVC` data to eidas-middleware@governikus.de. The CHR can be
        found in the admin interface on the detail page of your provider. Once the new TLS certificate is stored in the
        :term:`Authorization CA`, you will receive a reply and you can renew your :term:`CVC`.

#.  **database connection**

    The default settings in this connection should be sufficient for most users. However you can change the database location, user name and password.

#.  **logging**

    The default location for the log files is ``/var/log/eidas-middleware/eidas-middleware.log``.

#.  **HSM**

    Set the ``hsm.type`` to ``PKCS11`` in case you want to use an HSM, or ``NO_HSM`` to use none.
    The other settings are only relevant if you use an HSM:

    You need to provide a configuration file for the Sun PKCS#11 provider.
    In this file, you need to configure the settings for your HSM model which is out of scope
    of this documentation. You can find assistance for the settings in the `PKCS#11 Reference Guide
    <https://docs.oracle.com/en/java/javase/11/security/pkcs11-reference-guide1.html>`_.
    Then, the path to the configuration file must be given as ``pkcs11.config`` property

    You must also provide the login password for the HSM (default user, not SO) as ``pkcs11.passwd``.
    It is assumed that this account already exists when you start the middleware, so you need to
    initialize the HSM beforehand.

    You can optionally enter a period (in days) after which expired keys are deleted from the HSM.
    Use ``hsm.keys.delete``. If you do not enter a value, a default of 30 days is assumed.
    Also, you can set whether you want to backup these keys in the database before they are deleted
    from the HSM via the ``hsm.keys.archive`` property. This option might not work with every HSM however.


Startup
-------

Once you have the ``application.properties`` configured and the HSM up and running (the latter only applicable
if you configured the use of an HSM), you can start the middleware application.
(see :ref:`startup_and_shutdown`)

Using the admin interface
-------------------------
As of eIDAS Middleware release 3.0.0, configuration and administration is mostly handled via web interface.
Only the settings are excluded, which must be given before application startup, i.e. in the ``application.properties``.

After the application has started, the admin interface is reachable with a web browser at
``https://<YOUR_SERVERURL>:<YOUR_ADMIN_PORT>/admin-interface``.

If it is the first time the application is started, you will be asked to set a password to protect access
to the admin interface. If you ever forget this password, you can reset by deleting the file ``password.properties``.


The admin interface offers the following configuration options:

Import/Export configuration
^^^^^^^^^^^^^^^^^^^^^^^^^^^

Here, you can download the existing configuration as an XML file, with our without inclusion of private keys.

If you already have an XML configuration file, it is possible to upload it here, but please use this with caution
as it will replace the existing configuration without further notice.

We provide XML samples for both the test and production environment, which can be uploaded and then completed
using the web interface.

.. attention::
    The upload function is not designed to handle POSeIDAS.xml from older middleware versions
    due to changed data structures. It can deal with exports from version 3.0.0+ only.


Key management
^^^^^^^^^^^^^^

This section deals with the management of keys and certificates. All key pairs and certificates you intend to use
must be uploaded and assigned a name for further reference here.

For uploading a key pair, you first need to upload the key store containing it.
Then extract the key pair from the key store.
Certificates can be uploaded directly or via key store and extraction.

Deletion of key pairs and certificates is also possible. However the application will refuse if the key or certificate
is still in use at some point in the configuration.

.. attention::
    For PKCS#12 key stores, it is expected that they follow the convention of having key passwords identical to the
    key store password.


eID service provider
^^^^^^^^^^^^^^^^^^^^

This section is for management of :term:`eID Service Providers<eID Service Provider>`.
Each entry requires a unique name and a unique client authentication key pair.

The name is used for identifying the :term:`eID Service Provider`.
In case the :term:`eID Service Provider` is dedicated for a private sector
eIDAS SP it is imperative that the name matches the ``providerName`` used in eIDAS SAML requests made by that SP.

The client authentication key pair is used for the communication to the :term:`Authorization CA`.
The associated certificate must be given to the :term:`Authorization CA`.
In case you use a PKCS11 HSM, this key must be stored in the HSM using label and ID identical to
the ``CVCRefID`` of the :term:`eID Service Provider` (usually the same value as the name).


eIDAS
^^^^^

In this area, the settings for the middleware as an eIDAS node are made.
You can fill in the information that will be published in the metadata and select the service provider that
will be used for requests from the public sector.
Especially important are the server URL, which must have the value as the middleware is reachable from
the internet, and the SAML key pairs. In case you use a PKCS#11 HSM, the key for SAML signatures must be
available in the HSM using label and ID ``samlsigning``.


eID means
^^^^^^^^^

This section allows to change the eID means accepted by the middleware. Please do not change this unless asked to do so.


Timer
^^^^^

Here, you can set the frequency for several background jobs. Normally the default settings should suffice.


DVCA
^^^^

Here, the settings for communication with the :term:`Authorization CA` (aka DVCA) are made.
For each :term:`Authorization CA` you need to create one configuration entry and later refer to the entries
in the respective service provider configurations.
The values for a single DVCA configuration (certificates and URLs) can be requested from the DVCA operator.

When configuring a new eIDAS Middleware, the certificate for the Master List trust anchor must be the currently used
Master List signer certificate or its issuer. After a successful update of the Master List, the Master List itself acts
as an additional trust anchor for future Master List updates. Therefore, the Master List trust anchor does not need to
be updated and it is fine to keep this certificate in the configuration, even if it expires.

.. hint:: In case the Master List cannot be updated because no valid trust anchor is present, contact the German SPOC
   or the Governikus eIDAS Middleware support to get the current Master List trust anchor.


Connector metadata
^^^^^^^^^^^^^^^^^^

In this area, you can configure the metadata files of eIDAS nodes which will connect to the middleware, as well as the
certificate to check the metadata signatures.

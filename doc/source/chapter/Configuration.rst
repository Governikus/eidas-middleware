.. _configuration-mw:

Configuration of the eIDAS Middleware application
=================================================

Neccessary keys and certificates
--------------------------------

In order to setup the middleware you will need to provide some keystores. The following overview illustrates the required certificates and keystores.

.. image:: ../images/Certs_and_Interfaces.png


The following table describes the individual keystores:

============================ =====================================
Keystore name                Description
============================ =====================================
BerCAClientKeystore          This keystore is needed to
                             access the :term:`Authorisation CA`.
ServerTLSKeystore            This keystore is used to setup
                             the HTTPS port of the server
SAMLSignKeystore             This keystore is used for
                             signing the outgoing SAML response
SAMLCryptKeystore            This keystore is used to decrypt
                             the incoming SAML requests
============================ =====================================

Please use only JKS or PKCS#12 keystores with their file name endings ``.jks``,  ``.p12`` or ``.pfx`` respectively.

It is advisable to create the BerCAClientKeystore in consultation with the respective :term:`Authorisation CA` as they might have additional requirements for the key.
They will also provide you with their TLS server certificate which needs to be entered into the configuration as well.

Be advised that the Common Name or Subject Alternative Name of the TLS Certificate must match with the URL of the middleware as it is reachable from the Internet.
This is important as the AusweisApp2 will check the URL in the authorisation certificate against the URL that is received from the eIDAS Middleware.
E.g., if the middleware is running on ``https://your.eidas.domain.eu/eidas-middleware/`` or ``https://your.eidas.domain.eu:8443/eidas-middleware/``, the CN or SAN of the TLS certificate must include ``your.eidas.domain.eu``.

For a test system, this TLS certificate may be self signed. However for a production system, this TLS certificate must meet the requirements of the `eIDAS Crypto Requirements, section 2.4 <https://ec.europa.eu/cefdigital/wiki/display/CEFDIGITAL/eIDAS+Profile?preview=/46992719/47190133/eidas_-_crypto_requirements_for_the_eidas_interoperability_framework_v1.0.pdf>`_ which states that qualified website certificates must be used.

Also make sure you have the metadata from your eIDAS connector stored in an xml file.


Using the configuration wizard
------------------------------
Starting with the release 1.0.3, the configuration wizard is available to ease the configuration of the eIDAS Middleware.

The configuration wizard is also a Spring Boot Application that uses a web application to create the necceassary configuration files for the eIDAS Middleware.
Because some of the configuration files contain absolute file paths, the configuration wizard should be executed on the same system as the eIDAS Middleware so that the correct file paths are present.
However the configuration wizard should only be started for the initial configuration and can be stopped before proceeding to normal operations.


Running the JAR
^^^^^^^^^^^^^^^
In case you are using the VirtualBox Image, change to `/opt/configuration-wizard`.
In case you are using your own environment, copy the JAR file to a folder of your choice.

You can start the application with the following command::

    java -jar configuration-wizard-1.0.5.jar

This way the configuration wizard will be available at `http://localhost:8080/config-wizard.`

To change the port or enable https, create a directory `config` in your working directory and paste the following lines into that file. Change the values of the properties according to your setup. ::

    server.port=443
    server.ssl.key-password=
    server.ssl.key-store=file:[/path/to/your/keystore]
    server.ssl.key-store-password=
    server.ssl.keyAlias=
    server.ssl.keyStoreType=[JKS/PKCS12]

After you have created the configuration, you can stop the configuration wizard by entering `CTRL+C`.


Using Docker to run the configuration wizard
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
The configuration wizard does not need a special configuration inside the container.
Therefore you can start, stop and remove the container as you like and create a new container
to run the wizard again whenever you need it.

To run the configuration wizard, execute the following command.
It will mount the named volume in the container so that the configuration wizard can store the configuration in the volume. ::

    docker run --rm -it -v eidas-configuration:/opt/eidas-middleware/configuration -p 8080:8080 --name eidas-configuration-wizard governikus/eidas-configuration-wizard:1.0.5

Running this command the configuration wizard will be available on http://localhost:8080/config-wizard.

For more information on starting and stopping containers and viewing the logs,
see the `Docker Docs <https://docs.docker.com/engine/reference/run/>`_.

To enable https, you must mount the keystore from the host to the container
and add environment variables for the Spring Boot application to use this keystore.
In this example, we assume that the keystore is located on the host at ``/home/user/keystore.jks``
with the alias ``localhost`` and the password ``123456`` for the keystore and the key as well.
You can also use PKCS12 keystores,
in this case you must change the value of ``SERVER_SSL_KEY_STORE_TYPE`` to ``PKCS12``. ::

    docker run --rm -it -v eidas-configuration:/opt/eidas-middleware/configuration -v /home/user/keystore.jks:/opt/eidas-middleware/keystore.jks -p 443:8080 -e SERVER_SSL_KEY_STORE=file:/opt/eidas-middleware/keystore.jks -e SERVER_SSL_KEY_STORE_TYPE=JKS -e SERVER_SSL_KEY_STORE_PASSWORD=123456 -e SERVER_SSL_KEY_ALIAS=localhost -e SERVER_SSL_KEY_PASSWORD=123456 --name eidas-configuration-wizard governikus/eidas-configuration-wizard:1.0.5

Because the application is now bound to the host in port 443,
the configuration wizard is available at https://localhost/config-wizard.

To stop and remove the container, just hit ``CTRL+C``.

To use this container with Docker Compose, see the example Docker Compose file at `GitHub <https://github.com/Governikus/eidas-middleware/blob/master/configuration-wizard/docker-compose/docker-compose.yaml>`_.
You can use docker-compose.yaml out of the box to start the configuration wizard without https. ::

    cd configuration-wizard/docker-compose
    docker-compose up

If you want to enable https, you can use the docker-compose-https.yaml file.
Please note that you must change the values for the path to the keystore on the host
and the values for the alias and passwords to match your keystore. ::

    cd configuration-wizard/docker-compose
    docker-compose -f docker-compose-https.yaml up

To stop the container, hit ``CTRL+C``. To remove the container afterwards, execute ``docker-compose down``.


General usage of the configuration wizard
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
After you have entered one of the previous mentioned URLs, you will see the configuration wizard in your browser.

The starting point of the configuration wizard depends whether a previous configuration is found or not.
In case of Docker, the path to the default configuration location in the Docker volume is automatically passed to the configuration wizard.
In case of using the VirtualBox image, the path to the configuration directory is `/opt/eidas-middleware/config`.

You can also upload existing configuration files from your local machine. Please note that in this case you must upload the referenced keystores as well.
We suggest to upload at least the POSeIDAS_TESTING.xml or POSeIDAS_PRODUCTION.xml so that you do not have to upload the trust anchors and enter the URLs.

After you may have uploaded previous configurations, you can go to the page `application.properties file configuration`.
As the name suggests, on this page the values for the `application.properties` for the eIDAS Middleware application are configured.

In order to select the keystore for the eIDAS Middleware, you must upload the keystore at the top of the page.
Then you can select this keystore in the drop down list.

In case of using Docker, the Database URL must be set to the following value::

    jdbc:h2:file:/opt/eidas-middleware/database/eidasmw;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE

Given you are not using Docker, it is also recommended to specify a directory for the log files.

You might also want to add additional properties to the file in case you want to enable debug logging or disable https because you are using a reverse proxy.
You can add these additional properties in the text area at the bottom.

On the next page the eID server of the eIDAS Middleware is configured.

The server URL is important especially if the middleware is running behind a reverse proxy.
It will be used for the POSeIDAS.xml and for SERVER_URL in the eidasmiddleware.properties.

The entity ID is used in the web admin of the middleware, you can use something like `providerA`.

The trust anchors and the server certificate are different for test and production environments. You find the right values int the POSeIDAS_PRODUCTION.xml and POSeIDAS_TESTING.xml.

The client authentication keystore is used for the communication to the :term:`Authorisation CA`.
The certificate of this keypair must be given to the :term:`Authorisation CA`.

On the next page the eIDAS adapter part of the eIDAS Middleware is configured.

You must upload the metadata of your eIDAS Connector and the certificate to verify the signature of the metadata.

You must also upload the middleware signature keystore that is used to sign the outgoing eIDAS responses and the middleware encryption keystore so that the eIDAS Connector has the option to encrypt the eIDAS requests.

You must also enter the two letter country code of your country.

You are also advised to enter some information about your organization that are available in the metadata of the eIDAS Middleware.

On the next page you can enter the location where the configuration for the eIDAS Middleware should be saved.
In case of Docker this should be `/opt/eidas-middleware/configuration`, in the other cases `/opt/eidas-middleware/config`.
Then you can save the configuration.


Editing the configuration files by hand
---------------------------------------
The configuration wizard should help you to configure the eIDAS Middleware, but it is not mandatory to use.
If you want to create or change the configuration manually, you can use the following information for more details for each value.


.. _setup-application-properties:

Setup the application.properties
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
The ``application.properties`` file is the main configuration file for a Spring Boot application.

Adjust the template located in ``/opt/application/config``:

.. literalinclude:: application.properties

This configuration file contains the following sections:

#.  **Server port**

    8443 is the default port which can be changed here.

#.  **TLS settings**

    To configure the TLS connection with your ServerTLSKeystore, insert the appropriate values in this section.

#.  **Database Connection**

    The default settings in this connection should be sufficient for most users. However you can change the database location, user name and password.

#.  **credentials for the POSeIDAS admin interface login**

    You must provide a hashed and salted password using bcrypt. A new hashed password can be created using the password generator provided as part of this distribution (``java -jar password-generator.jar yournewpassword``). Paste the output from that application into this section.

#.  **logging**

    The default location for the log files is /opt/var/eidas-middleware.


Setup the POSeIDAS.xml
^^^^^^^^^^^^^^^^^^^^^^
The ``POSeIDAS.xml`` file is the configuration file for the eID server component of the middleware. This is a separate file as the eID server will also be available as a standalone application without the eIDAS part, thus allowing for re-use of this file.

There are two different templates located at ``/opt/application/config``. ``POSeIDAS_TESTING.xml`` contains the PKI certificates and URLs for the test system, ``POSeIDAS_PRODUCTION.xml`` for the productive system. Rename the corresponding file to ``POSeIDAS.xml`` and adjust it.

.. literalinclude:: POSeIDAS.xml
    :language: xml

Additional details:

#.  **ServerUrl**

    Change only the hostname and port as it is reachable from the internet, e.g. https://german-middleware:443/eidas-middleware.

#.  **clientCertificate**

    Insert the Base64-encoded certificate from the BerCAClientKeystore.

#.  **clientKey**

    Insert the Base64-encoded private key from the BerCAClientKeystore.

#.  **PaosReceiverURL**

    Change only the hostname and port as it is reachable from the internet, e.g. https://german-middleware:443/eidas-middleware/paosreceiver.


Setup the middleware
^^^^^^^^^^^^^^^^^^^^
In addition to the following configuration you have to create a folder for the eIDAS connector metadata file. Typically this is a subfolder of ``/opt/application/config``.

This is the configuration file for the eIDAS component of the middleware. Please adjust the template located at ``/opt/application/config/eidasmiddleware.properties``:

.. literalinclude:: eidasmiddleware.properties

Additional details:

#.  **SERVICE_PROVIDER_CONFIG_FOLDER**

    Insert the path to the folder that contains the eIDAS connector metadata. The metadata must contain the file endling ``*.xml``.

#.  **SERVICE_PROVIDER_METADATA_SIGNATURE_CERT**

    Specify the certificate that corresponds to the private key which was used to sign the metadata.xml in the ``SERVICE_PROVIDER_CONFIG_FOLDER``.

#.  **ENTITYID_INT**

    Only change this value if you have changed the value ``entityID`` in the ``POSeIDAS.xml``.

#. **SERVER_URL**

    This value is used for the URL in the Middelware Metadata. Use the following format: https://servername:port

#.  **MIDDLEWARE_SIGN_KEY**

    Insert the path to the keystore that should be used to sign eIDAS responses.

#.  **MIDDLEWARE_SIGN_PIN**

    Specify the password for the keystore. The password for the key and keystore must be the same.

#. **MIDDLEWARE_SIGN_ALIAS**

    Specify the alias of the entry to be used from the keystore.

#.  **MIDDLEWARE_CRYPT_KEY**

    Insert the path to the keystore that should be used to decrypt eIDAS requests.

#.  **MIDDLEWARE_CRYPT_PIN**

    Specify the password for the keystore. The password for the key and keystore must be the same.

#. **MIDDLEWARE_CRYPT_ALIAS**

    Specify the alias of the entry to be used from the keystore.

#.  **ENTITYID**

    Specify the Entity ID that the middleware presents to the eIDAS Connector.

#.  **COUNTRYCODE**

    Specify the country where the middleware is deployed.

#. **CONTACT_PERSON_XXX and ORGANIZATION_XXX**

    Insert appropriate values for your organization and contact person.

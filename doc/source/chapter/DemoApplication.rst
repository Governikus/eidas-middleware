.. _eidasdemoapplication:

eIDAS Demo Application
======================
Starting with version 1.0.4, we provide a simple eIDAS Demo Application to test the eIDAS Middleware.
The eIDAS Demo Application is an eIDAS Connector that sends an eIDAS request to the middleware and
displays the returned eIDAS response.
This way you can verify that the eIDAS Middleware is working correctly.

Configuration of the eIDAS Demo Application
-------------------------------------------
Because the eIDAS Demo Application is a Spring Boot Application, the ``application.properties`` file is used to configure the eIDAS Demo Application.
It must contain the following content. Adapt all the values to match your setup. ::

    # The URL to the eIDAS Middleware
    middleware.samlreceiverurl=https://your.middleware.host:8443/eidas-middleware/RequestReceiver

    # The path to the certificate that can be used to verify the signature of the eIDAS responses from the Middleware
    middleware.signature.certificate=/path/to/your/middleware_signature.crt

    # The path to the keystore that will be used to sign the eIDAS request, jks or p12
    demo.signature.keystore=/path/to/your/demo_signature_keystore.p12

    # The alias for the demo_signature_keystore
    demo.signature.alias=alias

    # The pin of the keystore and key of the demo_signature_keystore
    demo.signature.pin=123456

    # The path to the keystore that will be used to decrypt the eIDAS responses from the Middleware
    demo.decryption.keystore=/path/to/your/demo_decryption_keystore.p12

    # The alias for the demo_decryption_keystore
    demo.decryption.alias=alias

    # The pin of the keystore and key of demo_decryption_keystore
    demo.decryption.pin=123456

    # Optional: Add a context path to the eIDAS Demo Application
    #server.contextPath=/eIDASDemoApplication

    # Optional: Change the port of the eIDAS Demo Application
    server.port=8080

The ``application.properties`` file must be present in your working directory or in a subdirectory called ``config`` of your working directory.


Using the eIDAS Demo Application
--------------------------------
To use the eIDAS Demo Application, start by running the eIDAS Demo Application.

#. Change to the correct directory where the aforementioned configuration is present.
#. If not present, copy the ``eidas-demo-2.2.6.jar`` file in this directory.
#. Start the application by executing ``java -jar eidas-demo-2.2.6.jar``.

Now you must configure your eIDAS Middleware to communicate with the eIDAS Demo Application.

#. Open the URL ``http://your.demo.host:8080/Metadata``. If you have changed the port or added a context path, adapt the URL to your configuration.
#. Right-click on the page in your browser and select ``Save as`` to save the Connector metadata of the eIDAS Demo Application.
#. Export the certificate from the demo_signature_keystore.
#. Stop the eIDAS Middleware.
#. Configure the eIDAS Middleware with this metadata and certificate:

     #) With the configuration wizard: Follow the instructions from :ref:`configuration-mw` but use these files when asked to upload the metadata of the connector and the corresponding signature certificate.
     #) Without the configuration wizard: Copy the metadata and the certificate on the machine that runs the eIDAS Middleware. Note that you must place the metadata in an empty directory. In the file ``eidasmiddleware.properties``, change the values of the properties ``SERVICE_PROVIDER_CONFIG_FOLDER`` to the new directory containing the metadata and ``SERVICE_PROVIDER_METADATA_SIGNATURE_CERT`` to the path of the certificate.

#. Start the eIDAS Middleware. Check the log for configuration errors.

Once you have configured the eIDAS Middleware, you are ready to test your system.

#. Open the URL ``http://your.demo.host:8080/NewRequesterServlet``.
#. Click on ``Go to the eIDAS Middleware``.
#. Click on ``Understood, start online identification`` to start the authorization procedure with your test eID card and the AusweisApp2.
#. Finally, you should be redirected to ``http://your.demo.host:8080/NewReceiverServlet``.

At the top you can see the full eIDAS SAML response with the encrypted SAML assertion.
Below that you can see the data from the test eID card.
If there was an error or the user aborted the authorization procedure, you would see the eIDAS SAML response with the status and unencrypted assertion containing more information why the error occurred.

There is also the possibility to demonstrate the eIDAS Middleware handling various errors.
Open the URL ``http://your.demo.host:8080/NewRequesterServlet``. The third part of the linklist sends
``LoA = Test`` with different error provocations. This test works without eID card and AusweisApp2. In this
demonstration also the CVC check is conducted. The result is shown if the CVC check wasn’t successful. If the CVC
check was successful the eIDAS Middleware is configured properly.

Using the eIDAS Demo Application in Docker
------------------------------------------
We provide an Docker image for the eIDAS Demo Application as well.
It can be found at `DockerHub <https://hub.docker.com/r/governikus/eidas-demo-application/>`_ .

Because the ``application.properties`` file and the referenced keystores must be mounted into the container, it is recommended to place the configuration file and the keystores and certificates in a single directory.
Also bear in mind that you must use the path of the container file system in the configuration when setting the keystores and certificates, e.g. ``middleware.signature.certificate=/opt/eidas-middleware/config/middleware_signature.crt``

To run the middleware, execute the following command after you have prepared the configuration, certificate and keystores::

    docker run --rm -it -v /path/to/your/config-directory:/opt/eidas-middleware/config -p 8080:8080 governikus/eidas-demo-application:2.2.6

Now you can follow the steps above to configure and test the eIDAS Middleware.

To stop the eIDAS Demo Application, execute ``CTRL+C``.

There is also a docker compose file available at `GitHub <https://github.com/Governikus/eidas-middleware/blob/master/eidas-demo/docker-compose/docker-compose.yaml>`_.
You can copy this file on your local machine and create a directory called configuration in your working directory.
Then copy the configuration file and the certificate and keystores in the configuration directory.
Afterwards you can run the container by executing ``docker-compose up``.
To stop and remove the container, first execute ``CTRL+C`` followed by ``docker-compose down``.

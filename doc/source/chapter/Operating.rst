.. include:: snmpshortcuts.rst

.. _operating:

Operating the server
====================================

.. _startup_and_shutdown:

Startup and shutdown
--------------------
The commands for starting and stopping vary between the different environments.

Plain eIDAS Middleware JAR
^^^^^^^^^^^^^^^^^^^^^^^^^^
If you choose to use just the JAR in your own environment, execute the following commands to start the
eIDAS Middleware. ::

    # cd into the folder where the eidas-middleware.jar is located in
    java -jar eidas-middleware.jar

If the configuration files are not located in a subdirectory called ``config`` of your current working directory, you
must specify the location of the configuration directory. Note that the path must end with a `/`::

    java -jar eidas-middleware.jar --spring.config.additional-location=file:/path/to/your/configuration-directory/

To stop the eIDAS Middleware execute ``CTRL+C``.
Alternatively you can also send ``SIGTERM`` with ``kill [PID of the Middleware]``.

Based on these commands you can write your own scripts for starting and stopping.

VirtualBox Image
^^^^^^^^^^^^^^^^
In the image you can execute the same commands as for the plain eIDAS Middleware JAR.
The JAR file is located in ``/opt/eidas-middleware``.

In addition to starting the Middleware directly, you can use systemd to start and stop the application.

.. code-block:: none

    sudo systemctl start eidas-middleware.service
    sudo systemctl stop eidas-middleware.service

To start the application on boot, execute the following line.

.. code-block:: none

    sudo systemctl enable eidas-middleware.service

.. hint::
    The eidas-middleware.service contains hard coded paths for the java installation and the name of the application.
    When you update or rename your java installation or the application, you must adapt the paths in the service file.

Docker
^^^^^^
The configuration and database of the Middleware are located in named volumes.
This way you can stop and remove the Middleware Docker container and create a new one to restart the application.

To run the eIDAS Middleware, execute the following command.
It will mount the named volumes containing the database and configuration in the container
and the application will be available on port 8443. ::

    docker run --rm -it -v eidas-configuration:/opt/eidas-middleware/configuration -v eidas-database:/opt/eidas-middleware/database -p 8443:8443 --name eidas-middleware-application governikus/eidas-middleware-application:3.4.0

To stop and remove the container, just hit ``CTRL+C``.

To keep the container running longer without being attached to the STDOUT and STDERR, change the command to
the following::

    docker run -d -v eidas-configuration:/opt/eidas-middleware/configuration -v eidas-database:/opt/eidas-middleware/database -p 8443:8443 --name eidas-middleware-application governikus/eidas-middleware-application:3.4.0

For more information on starting and stopping containers and viewing the logs,
see the `Docker Docs <https://docs.docker.com/engine/reference/run/>`_.

As mentioned before, the eIDAS Middleware application configuration is located in the named volume.
If you want to change the TLS key store or disable HTTPS because you are using a reverse proxy,
you should use the admin interface to modify the configuration
instead of adding environment variables to the Docker run command.

To use this container with Docker Compose, see the example Docker Compose file at `GitHub <https://github.com/Governikus/eidas-middleware/blob/master/eidas-middleware/docker-compose/docker-compose.yaml>`_.
You can use docker-compose.yaml out of the box to start the eIDAS Middleware application. ::

    cd eidas-middleware/docker-compose
    docker-compose up

To stop the container, hit ``CTRL+C``. To remove the container afterwards, execute ``docker-compose down``.


Obtain authorization certificate
--------------------------------

When the Middleware is running, direct your browser to the admin interface at
``https://<YOUR_SERVERURL>:<YOUR_ADMIN_PORT>/admin-interface``.

After logging in, you will see your :term:`eID Service Providers<eID Service Provider>` in the dashboard
(assuming you have already completed the configuration as in :ref:`configuration-mw`).
Please open the details for the provider you want to obtain the certificate for.

By clicking the button ``Start connection check`` you can check the connection to the :term:`Authorization CA`.
If this check does not succeed, take a look in the log for more details.
Possible errors are firewalls that block the connection to the :term:`Authorization CA` or the :term:`Authorization CA`
has not yet stored your client TLS server certificate.
If the error persists, send the log file and your error description to eidas-middleware@governikus.com.

You are also advised to create a :term:`Request Signer Certificate` before you send the initial request.
Navigate to the tab ``RSC``.

It is not required to specify a holder for public sector :term:`eID Service Provider`.
In this case, the RSC can be generated by pressing `Generate RSC` without specifying a holder.

For private sector :term:`eID Service Providers<eID Service Provider>`,
please enter the holder for the :term:`Request Signer Certificate`
assigned to the provider by the :term:`Authorization CA` and then press `Generate RSC`. The Holder for the private
sector consists of the country code and the Holder Mnemonic. If the Holder Mnemonic is not known, please contact
eidas-middleware@governikus.de to get the Holder Mnemonic.



If the request signer certificate has been successfully generated the button changes to
`Download RSC`. You can download the certificate and forward it to the PoSC or its representative
(production system) / :term:`Authorization CA` (test system).

If the connection check is successful and the :term:`Authorization CA` has confirmed that your Request Signer
Certificate had been processed, you can request the :term:`Authorization Certificate`.
To do that, fill in the form `Start an initial request` with the values that you should have received from the
:term:`Authorization CA`.
If the CA did not specify a sequence number, you can start with 1. Then click on `Send initial request to DVCA`.
If this request was unsuccessful, take a look in the log for more details and double check that the country code and
CHR Mnemonic are correct.
If the error persists, send the log file and your error description to eidas-middleware@governikus.com.

After a successful initial request the eIDAS Middleware should be ready to receive eIDAS requests from your eIDAS
connector.

The eIDAS Middleware automatically renews the :term:`Authorization Certificate`.
It also checks regularly for updates of the :term:`Block List`, :term:`Master List` and :term:`Defect List`.


Additional information
----------------------

Logging
^^^^^^^
The log level can be changed by adding properties to the ``application.properties``. ::

    # change the root level:
    logging.level.root=DEBUG
    # change the logging level only of the Middleware specific classes:
    logging.level.de.governikus=DEBUG

For more information, see the `Spring Boot documentation <https://docs.spring.io/spring-boot/docs/current/reference/html/boot-features-logging.html#boot-features-logging>`_.

.. hint::
    Log level info is recommended for productive operation. The debug level should only be used if a problem needs to be
    analyzed.

Startup checks
^^^^^^^^^^^^^^
The Middleware performs some checks when it is started. In detail, these are:

* Is the TLS server certificate valid?
* Is the :term:`Authorization Certificate` valid?
* Does the server URL match the one in the :term:`Authorization Certificate`?
* Is the TLS server certificate correctly referenced in the :term:`Authorization Certificate`?

The results of these checks can be found in the log. Failed checks are reported as warnings,
while successful checks are logged on the info level. Also, you can see the results in the admin interface
and trigger a rerun of the checks there.

.. Note::
    The check for TLS server certificate validity performs a call to the server URL in order to retrieve the
    certificate. If this call is blocked, or routed to a different point than calls originating from the internet,
    you may experience false negative results.


VirtualBox Image
^^^^^^^^^^^^^^^^
The operating system is configured to use the official Debian sources for updates. Please make sure that updates are
installed on a regular basis. To update the operating system issue the following commands:
``apt-get update && apt-get upgrade``

When using systemd, the eIDAS Middleware log files can be found in the directory ``/var/log/eidas-middleware``.


Scalability
^^^^^^^^^^^
The performance of the eIDAS Middleware improves by adding more memory (RAM) and using a faster CPU.
In case the memory configuration has changed, the server needs to be restarted.
To start the JVM with more memory, add ``-Xmx`` with the new maximum memory size to the start command,
e.g. ``java -Xmx8g -jar eidas-middleware-3.4.0.jar`` for 8 GB.


Request Signer Certificate
^^^^^^^^^^^^^^^^^^^^^^^^^^
The Middleware supports :term:`Request Signer Certificates<Request Signer Certificate>`.
These are long-term certificates used to sign requests for
:term:`Authorization Certificates<Authorization Certificate>`, both initial and subsequent.
When you have not yet generated one, you can do so by clicking `Generate RSC`.
After that, the new request signer certificate will automatically be used for any
:term:`Authorization Certificate` request.

This is especially helpful to Middleware operators in case the :term:`Authorization Certificate`
expires before it has been renewed, as they can simply sign a new initial request using the
:term:`Request Signer Certificate` and do not need support by the :term:`Authorization CA`

However, in order to accept requests signed with the :term:`Request Signer Certificate`,
the :term:`Authorization CA` needs to know this certificate. You need to download the freshly
generated :term:`Request Signer Certificate` using `Download RSC` and forward
it to the PoSC or its reprensentative (production system) / :term:`Authorization CA` (test system).
As a fallback, the :term:`Authorization Certificate` requests are still signed using certificate chain method when the
:term:`Authorization CA` has not yet processed your new request signer certificate.

A :term:`Request Signer Certificate` is always valid for 3 years.

The current :term:`Request Signer Certificate` can be downloaded anytime by clicking the "Download RSC" button.

Automatic renewal of the request signer certificate
"""""""""""""""""""""""""""""""""""""""""""""""""""

The Middleware can automatically send new :term:`Request Signer Certificate` to the
:term:`Authorization CA`.
For security reasons, automatic renewal can only be performed if a :term:`Request Signer Certificate` is
already registered with the :term:`Authorization CA`.

A message is displayed in the admin interface if the :term:`Request Signer Certificate` must be sent manually
to the :term:`Authorization CA`. As soon as a :term:`Request Signer Certificate` is used by the Middleware, a
green tick "Is RSC in use:" is displayed in the Admin interface under the "RSC" tab in the "RSC Info" tile in
the eID Service Provider segment.

A timer checks daily whether the existing :term:`Request Signer Certificate`
needs to be renewed. By default, a :term:`Request Signer Certificate` is renewed 3 weeks before it expires and
the new :term:`Request Signer Certificate` is automatically sent to the :term:`Authorization CA`.

If the renewal fails, a message is displayed in the administration interface. The value when a
:term:`Request Signer Certificate` should be renewed can be adjusted in the timer configuration.

Manual renewal of the request signer certificate
""""""""""""""""""""""""""""""""""""""""""""""""

:term:`Request Signer Certificate` can also be renewed and sent to the :term:`Authorization CA`
manually via the admin interface.
In the Admin interface, there is a 'Generate And Send RSC' button under the 'RSC' tab in the eID Service Provider area.
By clicking on this button, a new :term:`Request Signer Certificate` is generated and sent to the
:term:`Authorization CA`.

If the process was not successful, an error is displayed in the admin interface.
If a new pending :term:`Request Signer Certificate` was created but not successfully sent to the
:term:`Authorization CA`, an attempt can be made to resend the pending :term:`Request Signer Certificate` to the
:term:`Authorization CA`. Please check the logs first or contact eidas-middleware@governikus.de to find out which
problem is preventing the renewal.

If you want to delete the pending RSC, click on the "Delete Pending RSC" button.

Automatic renewal of expired authorization certificates
"""""""""""""""""""""""""""""""""""""""""""""""""""""""

In case an :term:`Authorization Certificate` has expired,
a new :term:`Authorization Certificate` can be requested automatically with a request signer certificate.
As long as the expiration date of the :term:`Authorization Certificate` is not more than two days ago,
an attempt is made every six hours to request a new :term:`Authorization Certificate` with the request signer
certificate. The message *"The CVC has expired. The system tries to renew the CVC in the background. Alternatively,
a manual initial request can be performed"* will be visible in that timespan.


.. _automatic_entanglement:

Automatic entanglement after TLS server certificate change
""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

To work properly, an :term:`Authorization Certificate` must have the hash of the TLS server certificate of this eIDAS
Middleware in its description.
This link between the :term:`Authorization Certificate` and the TLS server certificate is called entanglement.
The eIDAS Middleware checks in a configurable interval the entanglement of the servers TLS server certificate with the
:term:`Authorization Certificate` of each service provider.
If the following preconditions are met, the eIDAS Middleware entangles a new TLS server certificate and renews the
:term:`Authorization Certificate` automatically:

* The timer for automatic entanglement is activated.
* The service provider is enabled.
* The service provider has an :term:`Authorization Certificate`.
* The service provider has a :term:`Request Signer Certificate`.
* The :term:`Request Signer Certificate` of the service provider is known to the :term:`Authorization CA`.
* The eIDAS Middleware can reach its own configured URL and a TLS server certificate is found.
* The found TLS server certificate is not expired.
* The found TLS server certificate is not linked to the current :term:`Authorization Certificate`.


Automatic renewal of TLS client certificate
"""""""""""""""""""""""""""""""""""""""""""

The Communication between the :term:`Authorization CA` and the eIDAS Middleware is secured by TLS Client
Authentication. The TLS client certificate of the eIDAS Middleware is valid for 3 years. Starting from version 3.3.0,
the :term:`Authorization CA` offers an interface to automatically renew a TLS client certificate. To use
this service a valid :term:`Request Signer Certificate` is mandatory, as the request to the :term:`Authorization CA`
is signed with a :term:`Request Signer Certificate` and the :term:`Authorization CA` checks the signature
with the :term:`Request Signer Certificate` stored in the :term:`Authorization CA`. The use of an
:term:`Request Signer Certificate` is described in section 7.3.5.

The renewal of a TLS client certificate consists of two calls to the :term:`Authorization CA`. The first
request is a certificate signing request (CSR) which is sent to the :term:`Authorization CA`. The
:term:`Authorization CA` checks the CSR and provides a signed certificate, which will be pulled via a second request.
The eIDAS Middleware checks daily whether the current TLS client certificate is valid for less than 30 days.
If this is the case, a CSR is automatically generated and sent to the :term:`Authorization CA`. If a
CSR has already been sent, the system checks whether the new TLS client certificate can be retrieved from the
:term:`Authorization CA`. If it is successfully retrieved, the new TLS client certificate is automatically
stored in the configuration and used for future connections to the :term:`Authorization CA`.

A new key pair must be used to sign the CSR which will be generated by the eIDAS Middleware and used for the CSR.
As soon as the new certificate has been successfully retrieved from the :term:`Authorization CA`, the certificate
will automatically be stored in the configuration and used for the connection to the :term:`Authorization CA`.
The value for when a TLS client certificate should be renewed can be configured via the Admin UI under Timer
Configuration. The default value is 30 days.

The TLS client certificate can also be renewed manually via the Admin UI. In the Admin UI, you will find a
"TLS" tab in the "Service Provider Details" section. This page lists the expiry date of the current TLS client
certificate and, if a CSR already exists, the date from which the new TLS client certificate can be pulled from
:term:`Authorization CA`.
On the right-hand side, a button is available to generate a new CSR and send it to the :term:`Authorization CA`.
If no HSM is used, a drop-down menu is shown above the "Generate and Send CSR" button in which the key to be
used for signing the CSR can be selected. The 'Generate New Key Pair' is preset. If the eIDAS Middleware should
generate a new key pair, 'Generate New Key Pair' must be selected in the drop-down menu. It is recommended to
select 'Generate New Key Pair' so the security requirements are met. It is also possible to upload a key via the
Key Management. The key must a be an RSA key with at least 3072 bits length.

If an HSM is used, two radio buttons are available. You can select whether a new key pair should be generated
or a present key should be used. If a present key should be used, it must be generated by the operator beforehand,
using the "CVCRefID" of the service provider plus the suffix "-PendingTLS" as a label, for example
"providerA-PendingTLS". The CVCRefID of the service provider can be found in the XML configuration of the
eIDAS Middleware, which can be downloaded via the Admin UI on the import/export configuration page.
This allows the operator to generate a key in the HSM that should be used. Please be aware that currenty only
RSA keys with at least 3072 bits are supported.

As soon as a CSR has been created and successfully received by the :term:`Authorization CA`, the new
TLS client certificate can be pulled via the Admin UI. The information on when the new TLS client certificate
is available for collection is displayed on the left-hand side by the date and time 'Not Poll Before'. When the
time has been reached from which the TLS client certificate can be collected, the new TLS client certificate can
be pulled by clicking the 'Poll Client Certificate' button. If the new TLS client certificate has been successfully
received, the new TLS client certificate is automatically activated in the configuration and will be used for
the connection to the :term:`Authorization CA`.
It is also possible to delete a pending CSR by clicking the button 'Delete Pending CSR'.

.. attention::
   Please note that a manual renewal should only be performed after careful consideration or at the request of
   the support team.


Monitoring
--------------------------------------------------

SNMP Agent (system)
^^^^^^^^^^^^^^^^^^^

The virtual machine we provide has a system :term:`SNMP` agent enabled by default and preconfigured.
With this agent, you can monitor the health status of the server using the SNMP tools of your choice.
You can change the SNMP settings by editing the file ``/etc/snmp/snmpd.conf``.

The configured user name is ``gov`` with authentication protocol SHA and privacy protocol DES, both
passwords ``12345678``.

For example, a snmpwalk on OID 1.3.6.1.2.1.25.4.2.1.4 (HOST-RESOURCES-MIB::hrSWRunPath) will reveal the running
processes.

``snmpwalk -v3 -l authPriv -u gov -a SHA -A 12345678 -x DES -X 12345678 $HOSTNAME 1.3.6.1.2.1.25.4.2.1.4``

Check the output on whether it contains ``java``.

You can monitor CPU, network and memory consumption with the usual OIDs, see `SNMP Documentation
<http://www.debianadmin.com/linux-snmp-oids-for-cpumemory-and-disk-statistics.html>`_ for details.

The following example will show the total RAM usage:

``snmpget -v3 -l authPriv -u gov -a SHA -A 12345678 -x DES -X 12345678 $HOSTNAME 1.3.6.1.4.1.2021.4.6.0``


SNMP Agent (application)
^^^^^^^^^^^^^^^^^^^^^^^^

The Middleware application itself also has an internal SNMP agent which can be used to query various data
directly from the application (see below for what is available).
Please note this is a different agent than the one for the system. The system agent is only preconfigured
in the virtual machine, the internal agent is available directly in the Middleware application. If you intend
to use both in parallel, you have to make sure that they run on different ports.

To activate the internal SNMP agent it is necessary to set ``poseidas.snmp.username``, ``poseidas.snmp.authpwd``
(authentication password) and ``poseidas.snmp.privpwd`` (encryption password) in the application.properties.
The passwords have a minimum length of 8 characters. The SNMP agent supports ``GET`` and
``GET NEXT`` requests.

Optional properties are ``poseidas.snmp.authalgo`` (authentication algorithm) with one of these values:
md5, sha, hmac128sha224, hmac192sha256, hmac256sha384, hmac384sha512 (hmac384sha512 is the default value when not set),
``poseidas.snmp.privalgo`` (encryption algorithm) with one of these values: des, 3des, aes128, aes192, aes256
(aes256 is the default value when not set).

There are two different ways to use the SNMP agent to monitor the application. It is divided in ``GET`` and ``TRAP``.

Optional properties for ``GET`` and ``GET NEXT`` requests can be set in the application.properties:
``poseidas.snmp.agenthost`` with the default value set to localhost and ``poseidas.snmp.agentport`` with the default
value set to port 161.

For monitoring the ``TRAPs`` it is also necessary to set ``poseidas.snmp.managementhost`` in the
application.properties.

Optional property for ``TRAP`` is ``poseidas.snmp.managementport`` (port 162 is the default value when not
set).

All existing SNMP GET values are explained in detail in the MIB located at
``https://github.com/Governikus/eidas-middleware/blob/3.4.0/poseidas/snmp/EIDASMW-SNMP-MIB.mib``.

Global GET
''''''''''

.. csv-table::
    :widths: 75 50 45
    :delim: ;

    OID; GET (Return value datatype); Description
    |CRL_GET_LAST_SUCCESSFUL_RETRIEVAL|; lastSuccessfulCRLRetrieval (DateAndTime); The timestamp for the last successful retrieval of a certificate revocation list is returned
    |CRL_GET_AVAILABLE|; isCRLAvailable (Integer32); 0: A certificate revocation list is present. 1: No certificate revocation list is present
    |GET_TLS_CERTIFICATE_VALID|; tlsCertificateExpirationDate (DateAndTime); Expiration date of the server certificate


Provider specific GET
'''''''''''''''''''''

Governikus OID = |GOVERNIKUS_OID|
eIDAS Middleware prefix = |EUMW_PREFIX|
Get prefix = |GET_PREFIX|

.. csv-table::
    :widths: 75 45 50
    :delim: ;

    OID; GET (Return value datatype); Description
    |PROVIDER_NAME_GET|; serviceProviderName (OCTET STRING); The service provider name used for identifying instances of the columnar objects in the serviceProviderTable
    |CVC_GET_PRESENT|; cvcPresent (Integer32); CVC present: 0 = not present, 1 = present
    |CVC_GET_VALID_UNTIL|; cvcExpirationDate (DateAndTime); Date until the CVC is valid
    |CVC_GET_SUBJECT_URL|; cvcSubjectUrl (OCTET STRING); The Subject URL of the CVC
    |CVC_GET_TLS_CERTIFICATE_LINK_STATUS|; cvcAndTlsLinked (Integer32); TLS server certificate referenced in CVC: 0 = not linked, 1 = linked
    |BLACKLIST_GET_LIST_AVAILABLE|; blackListAvailable (Integer32); Block List availability: 0 = not available, 1 = available
    |BLACKLIST_GET_LAST_SUCCESSFUL_RETRIEVAL|; lastBlackListRenewal (DateAndTime); Date of last successful Block List renewal
    |BLACKLIST_GET_DVCA_AVAILABILITY|; blackListCAAvailable (Integer32); Block List PKI availability: 0 = not available, 1 = available
    |MASTERLIST_GET_LIST_AVAILABLE|; masterListAvailable (Integer32); Master List availability: 0 = not available, 1 = available
    |MASTERLIST_GET_LAST_SUCCESSFUL_RETRIEVAL|; lastMasterListRenewal (DateAndTime); Date of last successful Master List renewal
    |MASTERLIST_GET_DVCA_AVAILABILITY|; masterListCAAvailable (Integer32); Master List PKI availability: 0 = not available, 1 = available
    |DEFECTLIST_GET_LIST_AVAILABLE|; defectListAvailable (Integer32); Defect List availability: 0 = not available, 1 = available
    |DEFECTLIST_GET_LAST_SUCCESSFUL_RETRIEVAL|; lastDefectListRenewal (DateAndTime); Date of last successful Defect List renewal
    |DEFECTLIST_GET_DVCA_AVAILABILITY|; defectListCAAvailable (Integer32); Defect List PKI availability: 0 = not available, 1 = available
    |RSC_GET_PENDING_AVAILABLE|; rscPendingAvailable (Integer32); Pending RSC availability: 0 = not available, 1 = available
    |RSC_GET_CURRENT_CERTIFICATE_VALID_UNTIL|; rscCurrentValidUntil (DateAndTime); Last date of RSC validity

TRAP
''''

The following table will show the OIDs and their meaning.

Governikus OID = |GOVERNIKUS_OID|
eIDAS Middleware prefix = |EUMW_PREFIX|
Trap prefix = |TRAP_PREFIX|

.. csv-table::
    :widths: 70 50 50
    :delim: ;

    OID; Description; Messages (Datetype)
    |CVC_TRAP_LAST_RENEWAL_STATUS|; The status of the last renewal of the CVC; 0 = success, 1 = failed (Integer32)
    |BLACKLIST_TRAP_LAST_RENEWAL_STATUS| ; The status of the last renewal of the Block List; 0 = renewed, 1 = no list received, 2 = list signature check failed, 3 = list processing error (Integer32)
    |BLACKLIST_TRAP_LAST_RENEWAL_PROCESSING_DURATION|; The last renewal processing duration of the Block List; The duration in milliseconds (long)
    |MASTERLIST_TRAP_LAST_RENEWAL_STATUS|; The status of the last renewal of the Master List; 0 = renewed, 1 = no list received, 2 = list signature check failed, 3 = list processing error (Integer32)
    |MASTERLIST_TRAP_LAST_RENEWAL_PROCESSING_DURATION|; The last renewal processing duration of the Master List; The duration in milliseconds (long)
    |DEFECTLIST_TRAP_LAST_RENEWAL_STATUS|; The status of the last renewal of the Defect List; 0 = renewed, 1 = no list received, 2 = list signature check failed, 3 = list processing error (Integer32)
    |DEFECTLIST_TRAP_LAST_RENEWAL_PROCESSING_DURATION|; The last renewal processing duration of the Defect List; The duration in milliseconds (long)
    |CRL_TRAP_LAST_RENEWAL_STATUS|; The status of the last renewal of the Certificate Revocation List; 0 = success, 1 = failed (Integer32)
    |RSC_TRAP_CHANGE_TO_CURRENT_RSC|; A pending Request Signer Certificate is now current; 0 = success, 1 = failed because there is no pending rsc, 2 = failed because there is no RefID (Integer32)
    |RSC_TRAP_NEW_PENDING_CERTIFICATE|; A new pending Request Signer Certificate has been generated; Certificate information (OCTET STRING)


Test mode
---------

The eIDAS Middleware includes a test mode to demonstrate handling various errors. To do this, a RequestedAuthnContext
must be added to the SAML request, e.g. ::

    <saml2p:RequestedAuthnContext Comparison="minimum">
        <saml2:AuthnContextClassRef xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">test</saml2:AuthnContextClassRef>
    </saml2p:RequestedAuthnContext>

Possible values are: ::

    test
    test#CANCELLATIONBYUSER
    test#WRONGPIN
    test#WRONGSIGNATURE
    test#CARDEXPIRED
    test#UNKNOWN

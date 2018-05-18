.. _operating:

Operating the server
====================================

.. _first_startup:

First time startup
------------------
After the middleware was configured successfully (see :ref:`configuration-mw`) you can start the application.

To check the connection to the :term:`Authorisation CA` and to receive the :term:`Authorisation Certificate`, open https://<YOUR_SERVERURL>/eidas-middleware/list in your Browser.
Enter the login credentials that you have configured earlier.

After logging in, you will see your :term:`eID Service Provider`. Click on the name to open the details.

At the top you can check the connection to the :term:`Authorisation CA`.
If this check does not succeed, take a look in the log for more details.
Possible errors are firewalls that block the connection to the :term:`Authorisation CA` or the :term:`Authorisation CA` has not yet stored your client TLS certificate.
If the error persists, send the log file and your error description to eidas-support@governikus.com.

However, after a successful connection make sure that you can request the :term:`Authorisation Certificate`.
To do that, fill in the form `Initial CVC Request to DVCA` with the values that you should have received from the :term:`Authorisation CA`.
If the CA did not specify a sequence number, you can start with 1. Then click on `Send initial request to DVCA`.
If this request was unsuccessful, take a look in the log for more details and double check that the country code and CHR Mnemonic are correct.
If the error persists, send the log file and your error description to eidas-support@governikus.com.

After a successful initial request the eIDAS Middleware should be ready to receive eIDAS requests from your eIDAS connector.

The eIDAS Middleware automatically renews the :term:`Authorisation Certificate`.
It also checks regularly for updates of the :term:`Black List`, :term:`Master List` and :term:`Defect List`.


.. _startup_and_shutdown:

Startup and shutdown
--------------------
The commands for starting and stopping vary between the different environments.

Plain eIDAS Middleware JAR
^^^^^^^^^^^^^^^^^^^^^^^^^^
If you choose to use just the JAR in your own environment, execute the following commands to start the eIDAS Middleware. ::

    # cd into the folder where the eidas-middleware.jar is located in
    java -jar eidas-middleware.jar

If the configuration files are not located in a subdirectory called `config` of your current working directory, you must specify the location of the configuration directory. Note that the path must end with a `/`::

    java -jar eidas-middleware.jar --spring.config.location=file:/path/to/your/configuration-directory/

To stop the eIDAS Middleware execute `CTRL+C`.
Alternatively you can also send `SIGTERM` with `kill [PID of the middleware]`.

Based on these commands you can write your own scripts for starting and stopping.

VirtualBox Image
^^^^^^^^^^^^^^^^
In the image you can execute the same commands as for the plain eIDAS Middleware JAR.
The JAR file is located in `/opt/eidas-middleware`.

In addition to starting the middleware directly, you can use systemd to start and stop the application.

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
The configuration and database of the middleware are located in named volumes.
This way you can stop and remove the middleware Docker container and create a new one to restart the application.

To run the eIDAS Middleware, execute the following command.
It will mount the named volumes containing the database and configuration in the container
and the application will be available on port 8443 on . ::

    docker run --rm -it -v eidas-configuration:/opt/eidas-middleware/configuration -v eidas-database:/opt/eidas-middleware/database -p 8443:8443 --name eidas-middleware-application eidas-middleware-application

To stop and remove the container, just hit ``CTRL+C``.

To keep the container running longer without being attached to the STDOUT and STDERR, change the command to the following::

    docker run -d -v eidas-configuration:/opt/eidas-middleware/configuration -v eidas-database:/opt/eidas-middleware/database -p 8443:8443 --name eidas-middleware-application eidas-middleware-application

For more information on starting and stopping containers and viewing the logs,
see the `Docker Docs <https://docs.docker.com/engine/reference/run/>`_.

As mentioned before, the eIDAS Middleware application configuration is located in the named volume.
If you want to change the TLS keystore or disable https because you are using a reverse proxy,
you should use the configuration wizard to modify the configuration
instead of adding environment variables to the Docker run command.

To use this container with Docker Compose, see the example Docker Compose file at `GitHub <https://github.com/Governikus/eidas-middleware/blob/master/eidas-middleware/docker-compose/docker-compose.yaml>`_.
You can use docker-compose.yaml out of the box to start the eIDAS Middleware application. ::

    cd eidas-middleware/docker-compose
    docker-compose up

To stop the container, hit ``CTRL+C``. To remove the container afterwards, execute ``docker-compose down``.


Additional information
----------------------

Logging
^^^^^^^
The log level can be changed by adding properties to the ``application.properties``. ::

    # change the root level:
    logging.level.root=DEBUG
    # change the logging level only of the middleware specific classes:
    logging.level.de.governikus=DEBUG

For more information, see the `Spring Boot documentation <https://docs.spring.io/spring-boot/docs/current/reference/html/boot-features-logging.html#boot-features-logging>`_.


VirtualBox Image
^^^^^^^^^^^^^^^^
The operating system is configured to use the official debian sources for updates. Please make sure that updates are installed on a regular basis. To update the operating system issue the following commands: ``apt-get update && apt-get upgrade``

When using systemd, the eIDAS Middleware log files can be found in the directory ``/var/log/eidas-middleware``.

Scalability
^^^^^^^^^^^
The performance of the eIDAS Middleware improves by adding more memory (RAM) and using a faster CPU.
In case the memory configuration has changed, the server needs to be restarted.
To start the JVM with more memory, add ``-Xmx`` with the new maximum memory size to the start command, e.g. ``java -Xmx8g -jar eidas-middleware-1.0.3.jar`` for 8 GB.


Monitoring
--------------------------------------------------
:term:`SNMP` is enabled by default and preconfigured. You can change the SNMP settings by editing the file
``/etc/snmp/snmpd.conf``.

The configured user name is ``gov`` with authentication protocol SHA and privacy protocol DES, both passwords ``12345678``.

You can monitor the health status of the server and the application using the SNMP tools of your choice.

For example, a snmpwalk on OID 1.3.6.1.2.1.25.4.2.1.4 (HOST-RESOURCES-MIB::hrSWRunPath) will reveal the running processes.

``snmpwalk -v3 -l authPriv -u gov -a SHA -A 12345678 -x DES -X 12345678 $HOSTNAME 1.3.6.1.2.1.25.4.2.1.4``

Check the output on whether it contains ``java``.

You can monitor CPU, network and memory consumption with the usual OIDs, see `SNMP Documentation
<http://www.debianadmin.com/linux-snmp-oids-for-cpumemory-and-disk-statistics.html>`_ for details.

The following example will show the total RAM usage:

``snmpget -v3 -l authPriv -u gov -a SHA -A 12345678 -x DES -X 12345678 $HOSTNAME 1.3.6.1.4.1.2021.4.6.0``

.. hint::
    If you want to use Nagios please refer to `Nagios Website <https://www.nagios.com/solutions/snmp-monitoring/>`_

.. _requirements:

Requirements
============
There are several requirements that have to be met in order to run the middleware successfully.
While some of them are automatically fulfilled when using the virtual machine image or Docker image, be advised to prepare your environment according to the following requirements if you choose to just use the eIDAS Middleware JAR file.

Software Requirements
---------------------

The eIDAS Middleware is a Spring Boot Application. This means that you can start the application with an JRE, there is no need for an application server. We support the latest available Zulu JDK in Version 8, at the time of this release this is 8u172.

For the operating system we support Debian 9.

Hardware Requirements
---------------------

For productive environments, we recommend the following requirements:
* 2 CPU Cores with at least 2 GHz
* 8 GB of RAM
* 10 GB of file system space

For test environments, we recommend the following requirements:
* 2 CPU Cores with at least 2 GHz
* 4 GB of RAM
* 10 GB of file system space

Network Requirements
--------------------

The eIDAS Middleware communicates with different parties, therefore a number of ports must be open and some external URLs must be reachable.

For a **Test-System** the following URLs need to be reachable::

    https://dev.governikus-eid.de:9444/gov_dvca/ta-service
    https://dev.governikus-eid.de:9444/gov_dvca/ri-service
    https://dev.governikus-eid.de:9444/gov_dvca/pa-service
    https://dev.governikus-eid.de:9444/gov_dvca/certDesc-service


For a **Production-System** the following URLs need to be reachable::

    https://berca-ps.d-trust.net/ps/dvca-at
    https://berca-ps.d-trust.net/ps/dvsd_v2
    https://berca-ps.d-trust.net/ps/scs
    https://berca-ps.d-trust.net/ps/dvca-at-cert-desc

In addition to that the eIDAS Middleware provides a port to listen for incoming eIDAS authentication requests as well as the communication with the users web browser and eID client.
While you can choose if you want to enable https in the eIDAS Middleware itself or use a reverse proxy to handle https, the before mentioned port must be open for incoming requests.

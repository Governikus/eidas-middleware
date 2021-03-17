.. _requirements:

Requirements
============
There are several requirements that have to be met in order to run the middleware successfully.
While some of them are automatically fulfilled when using the virtual machine image or Docker image, be advised to prepare your environment according to the following requirements if you choose to just use the eIDAS Middleware JAR file.

Software Requirements
---------------------

The eIDAS Middleware is a Spring Boot Application. This means that you can start the application with a JRE,
there is no need for an application server. We support the latest available Zulu JDK in Version 8,
at the time of this release this is 8u282.

For the operating system we support Debian 9 (LTS).

Hardware Requirements
---------------------

For productive environments, we recommend the following requirements:

* 4 CPU cores with at least 2 GHz
* 16 GB of RAM
* 100 GB of file system space

For test environments, we recommend the following requirements:

* 2 CPU cores with at least 2 GHz
* 4 GB of RAM
* 10 GB of file system space

Network Requirements
--------------------

The eIDAS Middleware communicates with different parties, therefore a number of ports must be open and some external URLs must be reachable.

For a **test system** the following URLs need to be reachable::

    https://dev.governikus-eid.de:9444/gov_dvca/ta-service
    https://dev.governikus-eid.de:9444/gov_dvca/ri-service
    https://dev.governikus-eid.de:9444/gov_dvca/pa-service
    https://dev.governikus-eid.de:9444/gov_dvca/certDesc-service

Governikus is in the process of replacing the old test CA with a new one. After migration the middleware will require
to reach these URLs::

    https://dvca-r1.governikus-eid.de/gov_dvca/ta-service
    https://dvca-r1.governikus-eid.de/gov_dvca/ri-service
    https://dvca-r1.governikus-eid.de/gov_dvca/pa-service
    https://dvca-r1.governikus-eid.de/gov_dvca/certDesc-service

Governikus will inform you when migration is due. Please do not change the CA settings on your own.

For a **production system** the following URLs need to be reachable::

    https://berca-p1.d-trust.net/ps/dvca-at
    https://berca-p1.d-trust.net/ps/dvsd_v2
    https://berca-p1.d-trust.net/ps/scs
    https://berca-p1.d-trust.net/ps/dvca-at-cert-desc

In addition to that the eIDAS Middleware provides a port to listen for incoming eIDAS authentication requests as well as the communication with the users web browser and eID client.
While you can choose if you want to enable https in the eIDAS Middleware itself or use a reverse proxy
to handle https, the aforementioned port must be open for incoming requests.

HSM support
-----------

As an optional feature, the eIDAS Middleware supports storing the most important private keys
in HSM instead of config files or databases. The middleware uses the PKCS#11 standard to communicate
with the HSM, which means that it should be able to function with any PKCS#11 compliant HSM.
However this cannot be guaranteed since we are unable to test every single HSM model.
We have successfully tested with SoftHSM.

Please note that due to limitations in the Sun PKCS#11 provider, the HSM cannot use the
RSA-PSS algorithms but only plain RSA. Using plain RSA is a violation of the eIDAS crypto requirements.
If you want to use an HSM and still comply to the requirements you should use EC keys.

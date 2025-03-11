.. _introduction:

Introduction to the German eID System
=====================================

The eIDAS Middleware performs the server side of the authentication procedure with the German eID.
It is an eIDAS Service providing cross-border authentication.
In contrast to an eIDAS Proxy Service which is operated by the Sending MS, the eIDAS Middleware
is provided by the Sending MS and every Receiving MS operates its own eIDAS Middleware instance.

The eIDAS Middleware consists of two parts:
Firstly, the Middleware contains an eID server to communicate with German eID backend systems
and with the user's browser and eID client.
Secondly, the Middleware contains a SAML adapter to communicate with the eIDAS connector of the Member State.

It should also be mentioned that the term `service provider` is ambiguous in this specific scenario:
In terms of the eIDAS environment, the service provider receives the authorization data from the
eIDAS connector to authenticate the user. However, in terms of the German eID system the service provider is
the SAML adapter of the Middleware, because this is the instance to which the eID server sends
the data from the eID card.

The German eID scheme fulfills all requirements of the eIDAS Level of Assurance **high**.
One of the major security-by-design feature is strong and mutual authentication between the relying party and the user.
For example, using authorization certificates is a strong cryptographic binding between the service provider and the user.
It is highly recommended to read the `German eID Whitepaper <https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/EIDAS/German_eID_Whitepaper_v1-4.pdf?__blob=publicationFile&v=2>`_ in order to understand the German eID scheme.
For additional information see the page about the `eIDAS Notification of the German eID <https://www.bsi.bund.de/EN/Themen/Oeffentliche-Verwaltung/Elektronische-Identitaeten/Online-Ausweisfunktion/eIDAS-Notifizierung/eidas-notifizierung_node.html>`_  and the `eID Infrastructure <https://www.bsi.bund.de/EN/Themen/Oeffentliche-Verwaltung/Elektronische-Identitaeten/Online-Ausweisfunktion/eID-Infrastruktur/eid-infrastruktur_node.html>`_.

The following brief description facilitates the understanding and configuration of the eIDAS Middleware.

A single eIDAS Middleware supports multiple :term:`eID Service Providers<eID Service Provider>` and multiple eIDAS connectors.
An :term:`eID Service Provider` needs an :term:`Authorization Certificate` to access data on the eID Card.
The Authorization Certificate is issued to the :term:`eID Service Provider` by the :term:`Authorization CA`, also called :term:`BerCA`.
The eIDAS Middleware technically receives the :term:`Authorization Certificate` via SOAP requests
to the :term:`Authorization CA`.
These requests are secured by TLS client authentication and signed with a so-called :term:`Request Signer Certificate`
or the currently valid :term:`Authorization Certificate`.
Therefore, the public certificates of the :term:`Authorization CA` and your eIDAS Middleware must be exchanged before the eIDAS Middleware requests the first Authorization Certificate.
If you decide to use a :term:`Request Signer Certificate` (which is highly recommended as it will become mandatory
at some point), this certificate must be given to the :term:`Authorization CA` as well.
For more information on how to get in contact with the :term:`Authorization CA`, see the `German eIDAS Middleware on the German Country Page <https://eidas.ec.europa.eu/efda/browse/notification/eid-chapter-contacts/DE>`_.
The :term:`Authorization Certificate` is presented to the German eID Card to ensure the authenticity of the :term:`eID Service Provider` and to verify that the :term:`eID Service Provider` only requests attributes allowed by the :term:`Authorization CA`.

There are two different Authorization CAs available. The Bundesdruckerei provides Authorization Certificates for productive environments with real eID cards.
Governikus provides Authorization Certificates for test environments with test eID cards.

Introduction to Docker
======================
In addition to running the Middleware in the provided virtual machine or
running the stand-alone Spring Boot application on your own server,
we provide a Docker Image to run the Middleware in a Docker container.

In order to keep the container as stateless as possible,
we use volumes to store the configuration and the HSQL database outside of the container.

Please note that it is not possible to run multiple Middleware containers
using the same configuration or database volume.

For information on running Docker containers, see the `Docker Docs <https://docs.docker.com/engine/reference/run/>`_.

We provide the Docker Image:

#. governikus/eidas-middleware-application (`Docker Hub <https://hub.docker.com/r/governikus/eidas-middleware-application>`_)

Two volumes are necessary to run the Middleware:

#. eidas-configuration
#. eidas-database

You can create these named volumes with the following command::

    docker volume create eidas-configuration
    docker volume create eidas-database

To reduce the hassle of executing long commands in the terminal,
we also provide Docker Compose files in addition to the Docker Images.
This way the configuration for running the containers can be stored in configuration files.
For more information on Docker Compose, see the `Docker Compose Docs <https://docs.docker.com/compose>`_.


Introduction to the VirtualBox Image
====================================
This section illustrates the requirements for the operational environment, including network configuration,
DNS configuration and firewall.

First time login via console
--------------------------------------------------
In order to configure network you have to login via console first.
Use ``eidasmw`` as username and ``Pleasechangeme!`` as password.
To change the system settings, you will have to use the ``sudo`` command.
Please reboot the system after configuration according to your environment and login via ``ssh``.

Regenerate the SSH server key
--------------------------------------------------
The virtual machine is shipped without SSH server keys. You must generate new keys before using the SSH server.
To generate new server keys execute the following commands:
::

    sudo dpkg-reconfigure openssh-server
    sudo /etc/init.d/ssh restart


Setting up network access
--------------------------------------------------
The network configuration is done in the file

``/etc/network/interfaces``

The default is configured to use DHCP. It is recommended to use a static configuration in your environment.
The file looks like:
::

    # This file describes the network interfaces available on your system
    # and how to activate them. For more information, see interfaces(5).

    source /etc/network/interfaces.d/*

    # The loopback network interface
    auto lo
    iface lo inet loopback

    # The primary network interface
    allow-hotplug enp0s3
    iface enp0s3 inet dhcp

We advise to remove the last line and instead add a block like::


    iface enp0s3 inet static
        address 1.1.1.2
        netmask 255.255.255.0
        gateway 1.1.1.1

and change the values to your specific setup.

* **address:** the IP address of this server
* **netmask:** the netmask of the used network
* **gateway:** the IP of the default gateway in this network segment



DNS configuration
--------------------------------------------------
The DNS configuration is done in the file

``/etc/resolv.conf``

The default values will probably not work in your environment!
Change the following with a text editor like ``vi`` to your own values.

* **domain:** name of your network domain, or comment it using ``#`` if not applicable
* **search:** name of your network domain, or comment it using ``#`` if not applicable
* **nameserver:** IP address of your name server(s), use multiple ``nameserver`` lines if there is more than one


Firewall configuration
--------------------------------------------------

The firewall is preconfigured, all incoming connections, except the pre-configured, are denied. The settings can be
found in this file:

``/etc/network/if-pre-up.d/iptables``

Pre-configured Ports:

* **ssh:** (TCP 22)
* **http:** (TCP 8080)
* **https:** (TCP 443, TCP 8443 and TCP 10000)
* **dhcp:** (UDP 67 and UDP 68)
* **snmp:** (UDP 161)

.. hint::
    Any outgoing and related or established connection is allowed. To see current firewall setup type ``iptables -L -n`` as root.


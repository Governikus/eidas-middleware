.. _glossary:

Glossary
====================================
.. glossary::
    :sorted:

    German eID PKI
        PKI for the German eID card. See `Country Verifying Certificate Authority - electronic Identity
        <https://www.bsi.bund.de/EN/Themen/Oeffentliche-Verwaltung/Elektronische-Identitaeten/Public-Key-Infrastrukturen/CVCA/Country-Verifying-Certificate-Authority-electronic-Identity/country-verifying-certificate-authority-electronic-identity_node.html>`_

    BerCA
        Part of the :term:`German eID PKI`, see :term:`Authorization CA`

    TLS
        Transport Layer Security.

    Key Store
        A place where keys and certificates are stored. Most often this is a file. Typical formats are
        :term:`PKCS#12` and :term:`Java Key Store`

    PKCS#12
        Format for key stores. See `RFC 7292 <https://datatracker.ietf.org/doc/html/rfc7292>`_

    Java Key Store
        Java Key Store. See `Wikipedia about JKS <https://en.wikipedia.org/wiki/Keystore>`_

    SNMP
        Simple Network Management Protocol (SNMP) is an internet standard protocol for collecting and
        organizing information about managed devices on IP networks and for modifying that information to change
        device behavior.

    eIDAS Middleware
        The Middleware as described in the eIDAS Technical Specification. See `collaborative platform created by
        the European Commission
        <https://ec.europa.eu/digital-building-blocks/wikis/display/DIGITAL/eIDAS+eID+Profile>`_

    Open Virtualization Format
        Open format for exchanging virtual machines.

    Authorization Certificate
        The :term:`Authorization CA` issues Authorization Certificates that enables the :term:`eID Service Provider`
        to read data from the German eID Card. The Authorization Certificate contains a set of attributes that the
        :term:`eID Service Provider` is allowed to access. It also contains the hash value of the SSL certificate of
        the :term:`eID Service Provider` so verify that the data of the eID Card is send to the correct consumer.
        Because the Authorization Certificates are only a couple of days valid, the eIDAS Middleware will renew them
        automatically before expiration.

    Authorization CA
        The Authorization CA issues :term:`Authorization Certificates<Authorization Certificate>` to eID Service Providers.
        The CA provides a SOAP Endpoint that is used by the eIDAS Middleware to request and renew
        :term:`Authorization Certificates<Authorization Certificate>`.

    eID Service Provider
        In the German eID scheme the Service Provider is the instance that initially receives the data from the eID Card.
        Therefore, in the eIDAS context the eID Service Provider is the eIDAS adapter of the Middleware and not the
        eIDAS Connector or eIDAS Service Provider.

    Black List
        See :term:`Block List`

    Block List
        When a card holder reports the eID Card as lost or authorities become aware that an eID card is lost or stolen,
        that eID will be revoked. The Block List contains all revoked eID. The list is :term:`eID Service Provider` specific
        and the eIDAS Middleware will check for every authorization request whether the eID Card is on that list.
        Note: the terms `Black List` and `Block List` refer to the same thing. Older versions of the specifications have coined
        the term `Black List` while newer versions have switched to `Block List`.

    Master List
        To verify the data from the eID Card is authenticated and has not been manipulated, digital signatures are used.
        The root certificates for these signatures are stored in the Master List.

    Defect List
        In case a batch of eID cards has a defect, the certificate that was used to sign the data on this batch of cards
        will be added to the Defect List.

    CVC
        Card Verifiable Certificate is the technical term for the :term:`Authorization Certificate`.

    Request Signer Certificate
        This is a long-term certificate used to sign requests for :term:`Authorization Certificates<Authorization Certificate>`.
        It will become mandatory at some point in the future, so it is highly recommended to start using it right away.

    CHR
        Certificate Holder Reference

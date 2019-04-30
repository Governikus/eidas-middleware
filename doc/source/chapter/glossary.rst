.. _glossary:

Glossary
====================================
.. glossary::
    :sorted:

    German eID PKI
        PKI for the German ID card. See `Country Verifying Certificate Authority - electronic Identity
        <https://www.bsi.bund.de/EN/Topics/ElectrIDDocuments/CVCAeID/CVCAeID_node.html>`_

    BerCA
        Part of the :term:`German eID PKI`, see :term:`Authorisation CA`

    TLS
        Transport Layer Security.

    Keystore
        A place where keys and certificates are stored. Most often this is a file. Typical formats are
        :term:`PKCS#12` and :term:`Java Keystore`

    PKCS#12
        Format for keystores. See `Wikipedia about PKCS12 <https://en.wikipedia.org/wiki/PKCS_12>`_

    Java Keystore
        Java Keystore. See `Wikipedia about JKS <https://en.wikipedia.org/wiki/Keystore>`_

    SNMP
        Simple Network Management Protocol (SNMP) is an Internet-standard protocol for collecting and
        organizing information about managed devices on IP networks and for modifying that information to change
        device behavior.

    eIDAS Middleware
        The middleware as described in the eIDAS Technical Specification. See `collaborative platform created by
        the European Commission
        <https://ec.europa.eu/cefdigital/wiki/display/CEFDIGITAL2018/eIDAS+Profile>`_

    Open Virtualization Format
        Open format for exchanging virtual machines.

    Authorisation Certificate
        The Authorisation CA issues Authorisation Certificates that enables the eID Service Provider`
        to read data from the German eID Card. The Authorisation Certificate contains a set of attributes that the
        eID Service Provider is allowed to access. It also contains the hash value of the SSL certificate of
        the eID Service Provider so verify that the data of the eID Card is send to the correct consumer.
        Because the Authorisation Certificates are only a couple of days valid, the eIDAS Middleware will renew them
        automatically before expiration.

    Authorisation CA
        The Authorisation CA issues Authorisation Certificates to eID Service Providers. The CA
        provides a SOAP Endpoint that is used by the eIDAS Middleware to request and renew Authorisation Certificates.

    eID Service Provider
        In the German eID scheme the Service Provider is the instance that initially receives the data from the eID Card.
        Therefore, in the eIDAS context the eID Service Provider is the eIDAS adapter of the Middleware and not the
        eIDAS Connector or eIDAS Service Provider.

    Black List
        When a card holder reports the eID Card as lost or authorities become aware that an eID card is lost or stolen,
        that eID will be revoked. The Black List contains all revoked eID. The list is :term:`eID Service Provider` specific
        and the eIDAS Middleware will check for every authorization request whether the eID Card is on that list.

    Master List
        To verify the data from the eID Card is authenticated and has not been manipulated, digital signatures are used.
        The root certificates for these signatures are stored in the Master List.

    Defect List
        In case a batch of eID cards has a defect, the certificate that was used to sign the data on this batch of cards
        will be added to the Defect List.

    CVC
        CVC (Card Verifiable Certificate) is the technical term for the :term:`Authorisation Certificate`.

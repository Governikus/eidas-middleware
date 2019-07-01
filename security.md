# German eIDAS Middleware security related information

This document outlines security related information 
regarding this project.

  * [General Information](#general-information)
  * [Verifying the integrity of the software packages](#verifying-package)
  * [Comments on this Policy](#comments-on-this-policy)
  * [PGP Key](#PGP-Key)
  * [S/MIME Certificate](#SMIME)

## General Information

The German eIDAS-Middleware implements the eIDAS technical 
specifications Version 1.1 see 
[eIDAS-Specs](https://ec.europa.eu/cefdigital/wiki/display/CEFDIGITAL2018/eIDAS+Profile). 
Any discussion on eIDAS infrastructure and security measures 
defined in the specification should be directed to your 
memberstate representive. So these issues can be discussed 
at the right places with the right people.

## Reporting Security Issues

We encourage you to report security issues with 
reference to the code contained in this repository. So please
*do* report any security issues you might find!

If you believe you have discovered a security vulnerability, 
please be responsible with your disclosure and report it to
``eid [at] bsi.bund.de`` instead of using GitHub's capabilities.
Please use encrypted mails. 

Find the required PGP-Key  [here](#PGP-Key)

## Verifying the integrity of the software packages

You can download the binary releases from github. 
We sign the application eidas-middleware-<version>.jar
using extended validation codesigning certificates
from GlobalSign. To verify the version 1.1.0 you could 
use the following example:

``jarsigner -verify -verbose eidas-middleware-1.1.0.jar`` 

You will see a lot of output text. Look for

``jar verified``

and 

``
Signed by "EMAILADDRESS=betrieb@governikus.de, 
CN=Governikus GmbH & Co. KG, 
O=Governikus GmbH & Co. KG, 
STREET=Am Fallturm 9, 
L=Bremen, ST=Bremen, 
C=DE, 
OID.1.3.6.1.4.1.311.60.2.1.1=Bremen, 
OID.1.3.6.1.4.1.311.60.2.1.2=Bremen, 
OID.1.3.6.1.4.1.311.60.2.1.3=DE, 
SERIALNUMBER=HRA 22041, 
OID.2.5.4.15=Private Organization`` 

at the end. 

## Comments on this Policy

If you have suggestions on how this process could be improved please submit a
pull request.

## PGP Key 

    -----BEGIN PGP PUBLIC KEY BLOCK-----
    Version: GnuPG v1

    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
    =DCy0
    -----END PGP PUBLIC KEY BLOCK-----
 

## S/MIME Certificate

    -----BEGIN CERTIFICATE-----
    MIIFDTCCA/WgAwIBAgIHAa6NJ/DWijANBgkqhkiG9w0BAQsFADBgMQswCQYDVQQG
    EwJERTEZMBcGA1UEChMQUEtJLTEtVmVyd2FsdHVuZzENMAsGA1UECxMEQnVuZDEn
    MCUGA1UEAxMeQ0EgSVZCQiBEZXV0c2NoZSBUZWxla29tIEFHIDE1MB4XDTE3MTAx
    MzEwMTAxNFoXDTIwMTAxMzIzNTk1OVowSzELMAkGA1UEBhMCREUxDTALBgNVBAoT
    BEJ1bmQxDDAKBgNVBAsTA0JTSTETMBEGA1UEAxMKR1JQOiBHUGVJRDEKMAgGA1UE
    BRMBMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMPCmjZagw3FHoap
    Kg7zjDdScBQze7IO6LNvyu5gFeewbSxzsg8gsRLmwLEYxPSawvHcVQsw+qoR+t0M
    xNONW4TlB9nJicnC9T4k24Fu6lpXVGV6M7ZYGg3wIsqY30kGS5r7X/20pglas/tI
    BUNCGrTcbh7XJb/wfEZmAVd8LjRVzGgHkusEtJo4sf2pNVrEKBFtxlPEnz2UUddq
    F3U2Ij3qaqGNhZ054zvXpfgvJhqnRXn0UYCEgqtzEl6ZMTEs5g5Y/LMilgLdin59
    M/RRzH4ImnWr3BFHhUObb5rCM2d9orJHOd8dU5852tIYzIdgFVi1P1xdoowdIx0c
    Y19rC6UCAwEAAaOCAd8wggHbMHIGA1UdIwRrMGmAFAwIqCjezDFaZCtW/6vkb9ti
    uKaRoUqkSDBGMQswCQYDVQQGEwJERTEZMBcGA1UEChMQUEtJLTEtVmVyd2FsdHVu
    ZzEcMBoGA1UEAxMTUENBLTEtVmVyd2FsdHVuZy0xNIIFAIkzzX0wGgYDVR0RBBMw
    EYEPZWlkQGJzaS5idW5kLmRlMIHhBgNVHR8EgdkwgdYwgdOggdCggc2Gb2xkYXA6
    Ly94NTAwLmJ1bmQuZGUvQ049Q0EgSVZCQiBEZXV0c2NoZSBUZWxla29tIEFHIDE1
    LE9VPUJ1bmQsTz1QS0ktMS1WZXJ3YWx0dW5nLEM9REU/Y2VydGlmaWNhdGVSZXZv
    Y2F0aW9uTGlzdIZaaHR0cDovL3g1MDAuYnVuZC5kZS9jZ2ktYmluL3Nob3dfYXR0
    cj9jbj1DQSUyMElWQkIlMjBEZXV0c2NoZSUyMFRlbGVrb20lMjBBRyUyMDE1JmF0
    dHI9Y3JsMBYGA1UdIAQPMA0wCwYJKwYBBAG9dAEBMA4GA1UdDwEB/wQEAwIF4DA9
    BggrBgEFBQcBAQQxMC8wLQYIKwYBBQUHMAGGIWh0dHA6Ly9vY3NwLml2YmIudGVs
    ZXNlYy5kZS9vY3NwcjANBgkqhkiG9w0BAQsFAAOCAQEATtzYTspSiP7/V1rjgZ3T
    ctEKyrWplGxqPZrXc4fNbFo0VNJgOcpMWY+aFjxiq7KMCMSGW71an+0PpXeKJ1cF
    YCLoxGD79PDwdXUH9ZcKs1TL14PehuqJPYP5MPXvv5HHDOhXzHGigeWWdJtAy8He
    /a5ih/du3Q2o63JlsWwjKP9k1L4XFzvRCF8UVRrwKZNgTvWrvmjRuXDgjr6VVHzu
    BvoGF/HQDjUI4OBWrww0BeoHN9btZ5gNGv6SKvYBpMeFySYpCNiy3exVvZgh748W
    tlXCui6Lhtl7XsWzB/jWAGt3iKq3mbWmzKSPSDic/V50fF6OfohTOM0bAILFNWwN
    6g==
    -----END CERTIFICATE-----



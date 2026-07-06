/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.eidasstarterkit;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.xml.namespace.QName;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactoryConfigurationError;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.core.xml.schema.XSAny;
import org.opensaml.core.xml.schema.impl.XSAnyBuilder;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Extensions;
import org.opensaml.saml.saml2.core.RequesterID;
import org.opensaml.saml.saml2.core.Scoping;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.core.impl.AuthnRequestBuilder;
import org.opensaml.saml.saml2.core.impl.ExtensionsBuilder;
import org.opensaml.saml.saml2.core.impl.RequesterIDBuilder;
import org.opensaml.saml.saml2.core.impl.ScopingBuilder;
import org.opensaml.xmlsec.encryption.support.EncryptionConstants;
import org.opensaml.xmlsec.encryption.support.EncryptionException;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.xml.sax.SAXException;

import de.governikus.eumw.eidascommon.ErrorCode;
import de.governikus.eumw.eidascommon.ErrorCodeException;
import de.governikus.eumw.eidascommon.Utils;
import de.governikus.eumw.eidascommon.Utils.X509KeyPair;
import de.governikus.eumw.eidasstarterkit.person_attributes.EidasPersonAttributes;
import de.governikus.eumw.eidasstarterkit.person_attributes.natural_persons_attribute.BirthNameAttribute;
import de.governikus.eumw.eidasstarterkit.person_attributes.natural_persons_attribute.CurrentAddressAttribute;
import de.governikus.eumw.eidasstarterkit.person_attributes.natural_persons_attribute.DateOfBirthAttribute;
import de.governikus.eumw.eidasstarterkit.person_attributes.natural_persons_attribute.FamilyNameAttribute;
import de.governikus.eumw.eidasstarterkit.person_attributes.natural_persons_attribute.GenderAttribute;
import de.governikus.eumw.eidasstarterkit.person_attributes.natural_persons_attribute.GenderType;
import de.governikus.eumw.eidasstarterkit.person_attributes.natural_persons_attribute.GivenNameAttribute;
import de.governikus.eumw.eidasstarterkit.person_attributes.natural_persons_attribute.PersonIdentifierAttribute;
import de.governikus.eumw.eidasstarterkit.person_attributes.natural_persons_attribute.PlaceOfBirthAttribute;

import lombok.SneakyThrows;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.xml.XMLParserException;


class TestEidasSaml
{

  private static final String EIDAS_EXTENSION_NAMESPACE_URI = "http://eidas.europa.eu/saml-extensions";

  private static final String EIDAS = "eidas";

  private static final String NAME = "Name";

  private static final String NAME_FORMAT = "NameFormat";


  private static final String METADATA_RSA_XML = """
    <?xml version="1.0" encoding="UTF-8"?><md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:alg="urn:oasis:names:tc:SAML:metadata:algsupport" xmlns:eidas="http://eidas.europa.eu/saml-extensions" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ID="eIDASSAMLDemo" entityID="https://autent-eumw-demo-head.govkg.de/Metadata" validUntil="2027-05-07T14:03:36.015Z"><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <ds:SignedInfo>
    <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1"/>
    <ds:Reference URI="#eIDASSAMLDemo">
    <ds:Transforms>
    <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
    <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    </ds:Transforms>
    <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
    <ds:DigestValue>LXx6EOAFWfIuhy2dRngf//MP/CoUt98ivA7AMMbYZrQ=</ds:DigestValue>
    </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue>
    CxmQjvIyWErZAp4di2gTKJzzlbSR7hy4UsXMV58T0D9xBWHs3hhvS9elREjAxhhk3hNkcXm2LScR&#13;
    xlNRK57R2b3jqWn1/WWVRaY3IvGBztyQgy6nZKehltNncKg9mrfSRD1Sea7Iyp5IdT57FRMO0X+x&#13;
    Hp+EAes3gHH2Eqm5TZ5da7nF5j0e6VF+hM88t33iPXPgRJAgVx4K3eNt9jcCQOZEeST25QKUtLjO&#13;
    jdq/Y+vHq+3CkDD+e84c4lL9lRzFhmdo0GpNz0/rDHBsWtd8m8qFUgjmQhh63o4h7Vj8M6PJ/yHD&#13;
    mNw8kgdSExYluf+aOxb9nj7HIAsSO1hXo8Wf3Z9mVYMfti0BiNTPTeTUKaWda6L+jUT7uprYgkEN&#13;
    kiMviES84Crtk12jBIa9IZvIXEUdJE5wDYlgNQwRF0/rxspQpSJVuM2I+BguXkhj8kP8EXqB2dFj&#13;
    +sssK5xGDKqnHf8DL/iBKOjlBZZVGQRYdGByy3acRswY6T1CgsX9N/RIQhfE39a6Y4lnd5ti95yX&#13;
    nPXG3PBhFeWf79Cfw++Zz9F3E12TzHvGhlvY//ssRwhV3NLw+a2duShelt+37ktdIHkvBxKhOKKn&#13;
    2icnDj3E5hWNMsx+y0NYaaORAPc+P7zJu7aA7VSemziXlk3ywwqy1bXuoX/tTozg5xW9tv4qrbs=
    </ds:SignatureValue>
    <ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIEsjCCApqgAwIBAgIUZxfRGUTKi8Z2S/Y0y1wBnbrVd14wDQYJKoZIhvcNAQELBQAwEzERMA8GA1UEAwwIZGVtby1zaWcwHhcNMjYwNDIzMTQ1NDA1WhcNMzEwNDIzMTQ1NDA1WjATMREwDwYDVQQDDAhkZW1vLXNpZzCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMLae4isFuL18ULgj2jCQJ4pWpQ1Ochi9HSL+ySs3gntPZ0Ljkopc0SeS+rKiZW0fm5MQ/36IMJfTpurnAWBuIfJuXWoytJvc4pFQ3QCAEg9TtLoc1kHxTilN5CL4cqGv4fNiB2rjnNPlC9UEuAwQrhyhsaI3WkGug2T9zjDm2T1IiwgcWX5ZlxST8lgrNraeCdbjbz75m8XYTtLTm3BWPM7UDhd+OBcn16fhN1162PUjtM1n65qmmH5hiBpexijbp1xE9ZkxPvCdyzbA21sEgrRFKsplI2ypJmKuyYLkNS6G9fLWS7BhGzG20cfEA4IxS7WV5uK379kxlPo+HvjiLimlXi39rQRMLa/vsWCH5QGBefsfpVai2LujkdtoHNA6cZSaig+ogqcUGoXtpt1q3IS09ZgzXWFkyjn/GazFfdYMwc3o2XID1pnRhVaITq0g60KLNW/1NdeCn3OaPGE/E0wfJVdNbRgUyV54LsmqSGIsk6NpDh/tqomluxjP/KCeSO4qo5h7YdgbhDn1Ere7b/sHCD3s8oWrSu8pv+LAI6NN4wJ0/9eqnTGnSgbpQWGYn2AxXN4vI/03O9jbJcaittGux9DpmOuXbXFeXpDlvHhnx0HBLZT1ypcnRn+rVTTkaclvBMwxPmQg3tQYvwucGG9mp5znbP2nrhyosNzIsXHAgMBAAEwDQYJKoZIhvcNAQELBQADggIBAInOJwjOlagtgwPJu/S2JWVUQE97RVQkgOxsIn6AFgZigsmBwux1nej8dBlL58gXdL3Dsqsb+EVD5T6WEHS5/Qx1gsV1aPEcT65hQOxiy9yop3Y7XYkTN1yOOeps42RrxZ9sqrWNNZCUob/ioQpg08SNBGDGRmXX7vgWqVCJ1kaHWdOgkPdm6jOvIB4P9klW/aTiIhHmQ5Yzq3ZYaocKOqArsK1aCKmBAPxIwxTA1Y5lzZeeKkKcNRetcs3217ubRlVQP88pI2kuCR5CV+UGGp+dPFUHXNFYL0dWgK7ahdwXQK4LvlZ/8HIEbvvGErnKBPalBPOSISgtIfRIY8j5RbP2jpb/nUJA0MxwxVbjr7tNaDlBzV4aE8dVEcfftnmh0C7PuA/S3a91lrZ0Wb6F9Sr8T+GLF63fzRcxkqWUlmoCeN5q0RWRBLRRIhZ03bwQLbK9sLdFI1eXO23uOLF1RSGdHi9lVVRjUDH10eUgPhUZDxvp/cwx+L6xAGC5GCfpwiYXMYIs3P2ioIzzhuDRnxw1vXpqW8AUlrYozOF2KYsjLZdRRfqX1Io4cX3eCDcTOgu9Uq92tmUWLe6OvtnehyRGNJDRHcjjxgBWPld0QzFLI3h2KQEDeQjtqyjCc3zfTbZ1aUsXPufW/lHoRmgC0o39Th7JWchLzwCqNiHYHSKm</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><md:Extensions><alg:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><alg:SigningMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256" MinKeySize="256"/><eidas:SPType>public</eidas:SPType><alg:SigningMethod Algorithm="http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1" MaxKeySize="4096" MinKeySize="3072"/></md:Extensions><md:SPSSODescriptor AuthnRequestsSigned="true" WantAssertionsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>MIIEsjCCApqgAwIBAgIUZxfRGUTKi8Z2S/Y0y1wBnbrVd14wDQYJKoZIhvcNAQELBQAwEzERMA8GA1UEAwwIZGVtby1zaWcwHhcNMjYwNDIzMTQ1NDA1WhcNMzEwNDIzMTQ1NDA1WjATMREwDwYDVQQDDAhkZW1vLXNpZzCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMLae4isFuL18ULgj2jCQJ4pWpQ1Ochi9HSL+ySs3gntPZ0Ljkopc0SeS+rKiZW0fm5MQ/36IMJfTpurnAWBuIfJuXWoytJvc4pFQ3QCAEg9TtLoc1kHxTilN5CL4cqGv4fNiB2rjnNPlC9UEuAwQrhyhsaI3WkGug2T9zjDm2T1IiwgcWX5ZlxST8lgrNraeCdbjbz75m8XYTtLTm3BWPM7UDhd+OBcn16fhN1162PUjtM1n65qmmH5hiBpexijbp1xE9ZkxPvCdyzbA21sEgrRFKsplI2ypJmKuyYLkNS6G9fLWS7BhGzG20cfEA4IxS7WV5uK379kxlPo+HvjiLimlXi39rQRMLa/vsWCH5QGBefsfpVai2LujkdtoHNA6cZSaig+ogqcUGoXtpt1q3IS09ZgzXWFkyjn/GazFfdYMwc3o2XID1pnRhVaITq0g60KLNW/1NdeCn3OaPGE/E0wfJVdNbRgUyV54LsmqSGIsk6NpDh/tqomluxjP/KCeSO4qo5h7YdgbhDn1Ere7b/sHCD3s8oWrSu8pv+LAI6NN4wJ0/9eqnTGnSgbpQWGYn2AxXN4vI/03O9jbJcaittGux9DpmOuXbXFeXpDlvHhnx0HBLZT1ypcnRn+rVTTkaclvBMwxPmQg3tQYvwucGG9mp5znbP2nrhyosNzIsXHAgMBAAEwDQYJKoZIhvcNAQELBQADggIBAInOJwjOlagtgwPJu/S2JWVUQE97RVQkgOxsIn6AFgZigsmBwux1nej8dBlL58gXdL3Dsqsb+EVD5T6WEHS5/Qx1gsV1aPEcT65hQOxiy9yop3Y7XYkTN1yOOeps42RrxZ9sqrWNNZCUob/ioQpg08SNBGDGRmXX7vgWqVCJ1kaHWdOgkPdm6jOvIB4P9klW/aTiIhHmQ5Yzq3ZYaocKOqArsK1aCKmBAPxIwxTA1Y5lzZeeKkKcNRetcs3217ubRlVQP88pI2kuCR5CV+UGGp+dPFUHXNFYL0dWgK7ahdwXQK4LvlZ/8HIEbvvGErnKBPalBPOSISgtIfRIY8j5RbP2jpb/nUJA0MxwxVbjr7tNaDlBzV4aE8dVEcfftnmh0C7PuA/S3a91lrZ0Wb6F9Sr8T+GLF63fzRcxkqWUlmoCeN5q0RWRBLRRIhZ03bwQLbK9sLdFI1eXO23uOLF1RSGdHi9lVVRjUDH10eUgPhUZDxvp/cwx+L6xAGC5GCfpwiYXMYIs3P2ioIzzhuDRnxw1vXpqW8AUlrYozOF2KYsjLZdRRfqX1Io4cX3eCDcTOgu9Uq92tmUWLe6OvtnehyRGNJDRHcjjxgBWPld0QzFLI3h2KQEDeQjtqyjCc3zfTbZ1aUsXPufW/lHoRmgC0o39Th7JWchLzwCqNiHYHSKm</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:KeyDescriptor use="encryption"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>MIIEsjCCApqgAwIBAgIUWRdbDuMxPVjpRWMHV20BnbrUx5MwDQYJKoZIhvcNAQELBQAwEzERMA8GA1UEAwwIZGVtby1lbmMwHhcNMjYwNDIzMTQ1MzIwWhcNMzEwNDIzMTQ1MzIwWjATMREwDwYDVQQDDAhkZW1vLWVuYzCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAOYMvg9eyLKVuTf7ur6SWn1jOIeOawtfaQbFO9TsHPqEILzSk/7PvL/7hb7MHSYhms5lgoiAVUg+vVN9vsgtf1U2nHn6v3j4u1Bq+5vtpaZDVlPUKE7UjLjL1FsaeTLWNwleaXUHPGK2LP1as/ONZCK0NJ+S9J6rXqsoOGP7sg6ujU1SHbVCY/wtZwCE+kiu8oERro0u3lEZ5OQYNjYnc+ZgsDubIoF2IZFpm/RIlXPm3+x0MmOx2YSgNX15D2wIkIlaABVF8fbnbx1/r5uMMTShKycG811a5jgoHpUy69NKiiMVRaYHQG3oZPZJ88gB+CsPowJc2Vcvu/xyLVdA6/rINBEt2WNGsl81psD3vvshfYdqKkgCoFVYnOezfcvIae0JdC/rRQdN6y0B2CSMKILHwsNVZVCAkqhGdGb2sYBO31JoEnQK/LfQ7+bc3FnOIeWvRtr0GVv4PlL5kqMbTkZclvdv9bhz53uudmCnkkPTDR5NKXJeyXSYm+PqUINrFbNSVTl06T81D+griW6JfTJxMOye4TBjy8RIEvPxRpLHvrY6HBvGdBt2ExY3IjpU/c7uP8VoXo3vlkVWnm7lOc5ZUqs/KGrEIfudOLslHOp5sqW9LW7r2zeCIx/c9yNIFB/lMcc3yYBWXGltyQXlvmiBfveCwBWCJgk7YyipYEt/AgMBAAEwDQYJKoZIhvcNAQELBQADggIBANl/p3zJoAtMcTDjMVyf9xlVnG9pEX2LStldkM2TdvTGjd3AF4EZ42JCLW2L0fdsShP0qekYYlXiQtLKD0OLf3MGKKroMQXfNPyI9ZNQMjhjnIYby1UTwRO2XmDqckbWW+yVd1XtxXc+8XKUgv0ib5vUSLSD81MzeJjuBB5HJI8slOmO40DICiaVhZkcwuuFjK7KgpHMOwx6uVjv0eu4V6cwqqbeNn75OuxFDG8gtElNpqfFH2YBu+xv6lRQi2IFoZeAIZWDGSrMcsE2bt5Al72KVvy74mLOxdi+3ED0D2GumfxdWrck68r94jQqBlJ/Vo9jvYB49RfIrU8edOTorHc6YgSG0zbPuxNBrW3KCN8DJoZPcMxjDjYtNkN1/mSEZyZ1WDQEXVaWCo1JYpM7AbZX3ks7wnhh68g8SDFTRCZElYK9KjT9S+sGrO//sBg2gxntJQ1ZRDHt+PoB0ohgT79P9zRFmQ3v1U4Cu+RmRuXqt5XqNsgeHOHO6BhrJA+2/bqTmcy9toN50n5Ymq+gbITvGozVMviWvIEAF3rayv1nxth17UUC2rAry77SU4rzBtk5r/h7B3Kf4WVUTJLGyN1UgIbaLH9Llv5fa38eiLXPx/e+4seEjbdff+JFBAjltPq1UHuI9UQjck7qGPvbEP7xl6njphEzQik7bP/GHz+m</ds:X509Certificate></ds:X509Data></ds:KeyInfo><md:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes256-gcm"/><md:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#rsa-oaep"><alg:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><xenc11:MGF xmlns:xenc11="http://www.w3.org/2009/xmlenc11#" Algorithm="http://www.w3.org/2009/xmlenc11#mgf1sha256"/></md:EncryptionMethod></md:KeyDescriptor><md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat><md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat><md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat><md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://autent-eumw-demo-head.govkg.de/NewReceiverServlet" index="1" isDefault="true"/></md:SPSSODescriptor><md:Organization><md:OrganizationName xml:lang="demo">demo</md:OrganizationName><md:OrganizationDisplayName xml:lang="demo">demo</md:OrganizationDisplayName><md:OrganizationURL xml:lang="demo">demo</md:OrganizationURL></md:Organization><md:ContactPerson contactType="technical"><md:Company>demo</md:Company><md:GivenName>demo</md:GivenName><md:SurName>demo</md:SurName><md:EmailAddress>demo</md:EmailAddress><md:TelephoneNumber>demo</md:TelephoneNumber></md:ContactPerson><md:ContactPerson contactType="support"><md:Company>demo</md:Company><md:GivenName>demo</md:GivenName><md:SurName>demo</md:SurName><md:EmailAddress>demo</md:EmailAddress><md:TelephoneNumber>demo</md:TelephoneNumber></md:ContactPerson></md:EntityDescriptor>
    """;

  private static final String METADATA_EC_XML = """
    <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:alg="urn:oasis:names:tc:SAML:metadata:algsupport" xmlns:eidas="http://eidas.europa.eu/saml-extensions" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ID="eIDASSAMLDemo" entityID="http://localhost:2002/Metadata" validUntil="2027-05-13T14:16:43.615Z">
    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <ds:SignedInfo>
    <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"/>
    <ds:Reference URI="#eIDASSAMLDemo">
    <ds:Transforms>
    <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
    <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    </ds:Transforms>
    <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
    <ds:DigestValue>BmlWZeB1GLdjHlYnYIJsN7DzFE76V0hmQQKda5Z86qw=</ds:DigestValue>
    </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue> JcG8Sr6Wf/bgD0UmPA7SZWJkQ+UD2HvGeazp1Di4mMRO1gLhDVoPkt8qKAczrPq2HYlrVkb2xorS BKfEF30QwA== </ds:SignatureValue>
    <ds:KeyInfo>
    <ds:X509Data>
    <ds:X509Certificate>MIIFkTCCAXmgAwIBAgIUazrvfLWb/zef6h/RHwgBniGxty8wDQYJKoZIhvcNAQELBQAwbTELMAkGA1UEBhMCREUxCzAJBgNVBAgMAkhCMQswCQYDVQQHDAJIQjETMBEGA1UECgwKR292ZXJuaWt1czERMA8GA1UECwwIQXV0ZW50LUExHDAaBgNVBAMME01JQyBsb2NhbCBDQSBST09UIDEwIBcNMjYwNTEzMTQxNTU1WhgPMjEyNjA1MTMxNDE1NTVaMGExCzAJBgNVBAYTAkRFMQswCQYDVQQIDAJIQjELMAkGA1UEBwwCSEIxEzARBgNVBAoMCkdvdmVybmlrdXMxETAPBgNVBAsMCEF1dGVudC1BMRAwDgYDVQQDDAd0ZXN0IEVDMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEvpPabc3eNSH/4efzvaWxzztVwJWUeIWBQmF+FyJsmnr0Hu0o083x2Tg5I+cPuzXLoIALThsaYsOPoosm+j/OhTANBgkqhkiG9w0BAQsFAAOCBAEAljbUKwS+UyDnQcbH60TsksSYMxUwjwoqMiMfiL/el9EkvDc35rT9TnmpDKqq6KWHia/a4ogXX1GrE/YffARnrBqLXnVm83SoOgoiJrtJGB73kBOXlRTATrKinFlRz/5E0WGIIFq0QTaVub44ClqcePdVQnBeQ5e3b/ntY8hOsZdY2CIJ3n3I+Hv5O+1EiK7OXyLXZQcSZp4PwiwVmOamQADQA2lALoh68/FML2BXuYLuykNhZ3zgpR7KbMYxiresMgNq8t+x0DV9l9+fYWCXhtQcFL9P5D746DztoGcpj5PYiTwN7c8m/hRfsSxA9s5lHZXhha2P69OMr95vRp+T0TDp5bRwSrhv2tnLmHk6XQh9l5zpSIPeqxzoCvaZq6cOTJsuXSam4JcgFBsdLMWvZiBDTUgXB6kcsdc67WnfzdcwfLr230skDFgqxbfvO+76ugbezCFmzpkQwHXcgSGwgCDi1I9GJd2ngq4E0AdT6EMIsIk928N0bJfmSW9c9tJL6Ez0lIKep7uiskD0Eu7lRdNQy4XEREaGPiW80Py+yPa5pQq9KIO3M81PnIwLjghR+ekI1u4DpLR3syMqvUPQSPIbMnm683rwII4tEoBE5qAqq2idSyAod3q8iZ1PKyBbM2tQKNHF6c8iuqVjx+RYQc9RTe85PkCglnrdSvARKO2CRbfmcmC85ys3eKMyfGBhqVCdc2t5hqVwjAH/OwW9yP4oWHvhIQLXIrUxtF+vPS2jHxLr2h6hch6DCu1aUl44MDZ7UhvxJiAdUQ/dyvJL40E0DgSGJn1ObcniciOCEr6ow/z9cQuW6Hi5bJETPpGw3bE7pHRkolwtBEQFUzA8w9MVwJpuW8r6B6XwGnu4JwrTtYzK38B3kfVw56tJ8P3TfJuwbmhgjxMcxwup/PpiEo3vLuw7ciIc4SpQHVFxIS8Tb0LjNsldSPxX234XTO2eqZmkunuJdB9XrCpKd6t8Uc1GDjsgJBPiRkIqmScOpwtSupHVdr7ejQHbIauBoaH3zsz6ylLOSJyKos/UScf+oKNFEut250nHOlP01Bx4tWbi1uggQtL+C3gz5in8oMR7vAhTZFXp5VMv71Xe8cKUw0cqvjNm7HBtOsIwwIbKlqmNMHzTLxH4rlpbLH3zXrNoqvk4pCsBYLJg7TdrY7cJmxCjvHZD3Ul6xModDGz/v4TTP2vaXgey2knN7jfqGVnbQtWcZvalxGeNRnoK7wrL6Cp9h4RuOAUUVV9LMrrpFoZ5ZCJTHcJmdJ3ztNONiCmJyJjyjD+PYax7SK8BZt/HnX79Ifcls74SBy/2Z0Xs1AzD+txKq4Nxv3+KnpwkJJFhnvF4eS0KkeZ9uD7h6YwgMA==</ds:X509Certificate>
    </ds:X509Data>
    </ds:KeyInfo>
    </ds:Signature>
    <md:Extensions>
    <alg:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
    <alg:SigningMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256" MinKeySize="256"/>
    <eidas:SPType>public</eidas:SPType>
    <alg:SigningMethod Algorithm="http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1" MaxKeySize="4096" MinKeySize="3072"/>
    </md:Extensions>
    <md:SPSSODescriptor AuthnRequestsSigned="true" WantAssertionsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
    <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <ds:X509Data>
    <ds:X509Certificate>MIIFkTCCAXmgAwIBAgIUazrvfLWb/zef6h/RHwgBniGxty8wDQYJKoZIhvcNAQELBQAwbTELMAkGA1UEBhMCREUxCzAJBgNVBAgMAkhCMQswCQYDVQQHDAJIQjETMBEGA1UECgwKR292ZXJuaWt1czERMA8GA1UECwwIQXV0ZW50LUExHDAaBgNVBAMME01JQyBsb2NhbCBDQSBST09UIDEwIBcNMjYwNTEzMTQxNTU1WhgPMjEyNjA1MTMxNDE1NTVaMGExCzAJBgNVBAYTAkRFMQswCQYDVQQIDAJIQjELMAkGA1UEBwwCSEIxEzARBgNVBAoMCkdvdmVybmlrdXMxETAPBgNVBAsMCEF1dGVudC1BMRAwDgYDVQQDDAd0ZXN0IEVDMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEvpPabc3eNSH/4efzvaWxzztVwJWUeIWBQmF+FyJsmnr0Hu0o083x2Tg5I+cPuzXLoIALThsaYsOPoosm+j/OhTANBgkqhkiG9w0BAQsFAAOCBAEAljbUKwS+UyDnQcbH60TsksSYMxUwjwoqMiMfiL/el9EkvDc35rT9TnmpDKqq6KWHia/a4ogXX1GrE/YffARnrBqLXnVm83SoOgoiJrtJGB73kBOXlRTATrKinFlRz/5E0WGIIFq0QTaVub44ClqcePdVQnBeQ5e3b/ntY8hOsZdY2CIJ3n3I+Hv5O+1EiK7OXyLXZQcSZp4PwiwVmOamQADQA2lALoh68/FML2BXuYLuykNhZ3zgpR7KbMYxiresMgNq8t+x0DV9l9+fYWCXhtQcFL9P5D746DztoGcpj5PYiTwN7c8m/hRfsSxA9s5lHZXhha2P69OMr95vRp+T0TDp5bRwSrhv2tnLmHk6XQh9l5zpSIPeqxzoCvaZq6cOTJsuXSam4JcgFBsdLMWvZiBDTUgXB6kcsdc67WnfzdcwfLr230skDFgqxbfvO+76ugbezCFmzpkQwHXcgSGwgCDi1I9GJd2ngq4E0AdT6EMIsIk928N0bJfmSW9c9tJL6Ez0lIKep7uiskD0Eu7lRdNQy4XEREaGPiW80Py+yPa5pQq9KIO3M81PnIwLjghR+ekI1u4DpLR3syMqvUPQSPIbMnm683rwII4tEoBE5qAqq2idSyAod3q8iZ1PKyBbM2tQKNHF6c8iuqVjx+RYQc9RTe85PkCglnrdSvARKO2CRbfmcmC85ys3eKMyfGBhqVCdc2t5hqVwjAH/OwW9yP4oWHvhIQLXIrUxtF+vPS2jHxLr2h6hch6DCu1aUl44MDZ7UhvxJiAdUQ/dyvJL40E0DgSGJn1ObcniciOCEr6ow/z9cQuW6Hi5bJETPpGw3bE7pHRkolwtBEQFUzA8w9MVwJpuW8r6B6XwGnu4JwrTtYzK38B3kfVw56tJ8P3TfJuwbmhgjxMcxwup/PpiEo3vLuw7ciIc4SpQHVFxIS8Tb0LjNsldSPxX234XTO2eqZmkunuJdB9XrCpKd6t8Uc1GDjsgJBPiRkIqmScOpwtSupHVdr7ejQHbIauBoaH3zsz6ylLOSJyKos/UScf+oKNFEut250nHOlP01Bx4tWbi1uggQtL+C3gz5in8oMR7vAhTZFXp5VMv71Xe8cKUw0cqvjNm7HBtOsIwwIbKlqmNMHzTLxH4rlpbLH3zXrNoqvk4pCsBYLJg7TdrY7cJmxCjvHZD3Ul6xModDGz/v4TTP2vaXgey2knN7jfqGVnbQtWcZvalxGeNRnoK7wrL6Cp9h4RuOAUUVV9LMrrpFoZ5ZCJTHcJmdJ3ztNONiCmJyJjyjD+PYax7SK8BZt/HnX79Ifcls74SBy/2Z0Xs1AzD+txKq4Nxv3+KnpwkJJFhnvF4eS0KkeZ9uD7h6YwgMA==</ds:X509Certificate>
    </ds:X509Data>
    </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:KeyDescriptor use="encryption">
    <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <ds:X509Data>
    <ds:X509Certificate>MIIFkTCCAXmgAwIBAgIUazrvfLWb/zef6h/RHwgBniGxty8wDQYJKoZIhvcNAQELBQAwbTELMAkGA1UEBhMCREUxCzAJBgNVBAgMAkhCMQswCQYDVQQHDAJIQjETMBEGA1UECgwKR292ZXJuaWt1czERMA8GA1UECwwIQXV0ZW50LUExHDAaBgNVBAMME01JQyBsb2NhbCBDQSBST09UIDEwIBcNMjYwNTEzMTQxNTU1WhgPMjEyNjA1MTMxNDE1NTVaMGExCzAJBgNVBAYTAkRFMQswCQYDVQQIDAJIQjELMAkGA1UEBwwCSEIxEzARBgNVBAoMCkdvdmVybmlrdXMxETAPBgNVBAsMCEF1dGVudC1BMRAwDgYDVQQDDAd0ZXN0IEVDMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEvpPabc3eNSH/4efzvaWxzztVwJWUeIWBQmF+FyJsmnr0Hu0o083x2Tg5I+cPuzXLoIALThsaYsOPoosm+j/OhTANBgkqhkiG9w0BAQsFAAOCBAEAljbUKwS+UyDnQcbH60TsksSYMxUwjwoqMiMfiL/el9EkvDc35rT9TnmpDKqq6KWHia/a4ogXX1GrE/YffARnrBqLXnVm83SoOgoiJrtJGB73kBOXlRTATrKinFlRz/5E0WGIIFq0QTaVub44ClqcePdVQnBeQ5e3b/ntY8hOsZdY2CIJ3n3I+Hv5O+1EiK7OXyLXZQcSZp4PwiwVmOamQADQA2lALoh68/FML2BXuYLuykNhZ3zgpR7KbMYxiresMgNq8t+x0DV9l9+fYWCXhtQcFL9P5D746DztoGcpj5PYiTwN7c8m/hRfsSxA9s5lHZXhha2P69OMr95vRp+T0TDp5bRwSrhv2tnLmHk6XQh9l5zpSIPeqxzoCvaZq6cOTJsuXSam4JcgFBsdLMWvZiBDTUgXB6kcsdc67WnfzdcwfLr230skDFgqxbfvO+76ugbezCFmzpkQwHXcgSGwgCDi1I9GJd2ngq4E0AdT6EMIsIk928N0bJfmSW9c9tJL6Ez0lIKep7uiskD0Eu7lRdNQy4XEREaGPiW80Py+yPa5pQq9KIO3M81PnIwLjghR+ekI1u4DpLR3syMqvUPQSPIbMnm683rwII4tEoBE5qAqq2idSyAod3q8iZ1PKyBbM2tQKNHF6c8iuqVjx+RYQc9RTe85PkCglnrdSvARKO2CRbfmcmC85ys3eKMyfGBhqVCdc2t5hqVwjAH/OwW9yP4oWHvhIQLXIrUxtF+vPS2jHxLr2h6hch6DCu1aUl44MDZ7UhvxJiAdUQ/dyvJL40E0DgSGJn1ObcniciOCEr6ow/z9cQuW6Hi5bJETPpGw3bE7pHRkolwtBEQFUzA8w9MVwJpuW8r6B6XwGnu4JwrTtYzK38B3kfVw56tJ8P3TfJuwbmhgjxMcxwup/PpiEo3vLuw7ciIc4SpQHVFxIS8Tb0LjNsldSPxX234XTO2eqZmkunuJdB9XrCpKd6t8Uc1GDjsgJBPiRkIqmScOpwtSupHVdr7ejQHbIauBoaH3zsz6ylLOSJyKos/UScf+oKNFEut250nHOlP01Bx4tWbi1uggQtL+C3gz5in8oMR7vAhTZFXp5VMv71Xe8cKUw0cqvjNm7HBtOsIwwIbKlqmNMHzTLxH4rlpbLH3zXrNoqvk4pCsBYLJg7TdrY7cJmxCjvHZD3Ul6xModDGz/v4TTP2vaXgey2knN7jfqGVnbQtWcZvalxGeNRnoK7wrL6Cp9h4RuOAUUVV9LMrrpFoZ5ZCJTHcJmdJ3ztNONiCmJyJjyjD+PYax7SK8BZt/HnX79Ifcls74SBy/2Z0Xs1AzD+txKq4Nxv3+KnpwkJJFhnvF4eS0KkeZ9uD7h6YwgMA==</ds:X509Certificate>
    </ds:X509Data>
    </ds:KeyInfo>
    <md:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes256-gcm"/>
    <md:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#kw-aes256"/>
    <md:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#ECDH-ES">
    <xenc11:KeyDerivationMethod xmlns:xenc11="http://www.w3.org/2009/xmlenc11#" Algorithm="http://www.w3.org/2009/xmlenc11#ConcatKDF">
    <xenc11:ConcatKDFParams>
    <ds:DigestMethod xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
    </xenc11:ConcatKDFParams>
    <enc:KA-Nonce xmlns:enc="http://www.w3.org/2001/04/xmlenc#">NONCE</enc:KA-Nonce>
    </xenc11:KeyDerivationMethod>
    </md:EncryptionMethod>
    </md:KeyDescriptor>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://localhost:2002/NewReceiverServlet" index="1" isDefault="true"/>
    </md:SPSSODescriptor>
    <md:Organization>
    <md:OrganizationName xml:lang="demo">demo</md:OrganizationName>
    <md:OrganizationDisplayName xml:lang="demo">demo</md:OrganizationDisplayName>
    <md:OrganizationURL xml:lang="demo">demo</md:OrganizationURL>
    </md:Organization>
    <md:ContactPerson contactType="technical">
    <md:Company>demo</md:Company>
    <md:GivenName>demo</md:GivenName>
    <md:SurName>demo</md:SurName>
    <md:EmailAddress>demo</md:EmailAddress>
    <md:TelephoneNumber>demo</md:TelephoneNumber>
    </md:ContactPerson>
    <md:ContactPerson contactType="support">
    <md:Company>demo</md:Company>
    <md:GivenName>demo</md:GivenName>
    <md:SurName>demo</md:SurName>
    <md:EmailAddress>demo</md:EmailAddress>
    <md:TelephoneNumber>demo</md:TelephoneNumber>
    </md:ContactPerson>
    </md:EntityDescriptor>
    """;

  // *.p12 used for tests.
  private static final String TEST_P12 = "/eidassignertest.p12";

  Map<EidasPersonAttributes, Boolean> requestedAttributes = new HashMap<>();

  @BeforeEach
  void setUp() throws Exception
  {

    EidasSaml.init();
    requestedAttributes.put(EidasNaturalPersonAttributes.BIRTH_NAME, true);
    requestedAttributes.put(EidasNaturalPersonAttributes.CURRENT_ADDRESS, false);
    requestedAttributes.put(EidasNaturalPersonAttributes.DATE_OF_BIRTH, true);
    requestedAttributes.put(EidasNaturalPersonAttributes.FAMILY_NAME, false);
    requestedAttributes.put(EidasNaturalPersonAttributes.FIRST_NAME, true);
    requestedAttributes.put(EidasNaturalPersonAttributes.GENDER, true);
    requestedAttributes.put(EidasNaturalPersonAttributes.PERSON_IDENTIFIER, true);
    requestedAttributes.put(EidasNaturalPersonAttributes.PLACE_OF_BIRTH, false);
  }

  @Test
  void createParseRequest() throws CertificateException, IOException, UnrecoverableKeyException, KeyStoreException,
    NoSuchAlgorithmException, NoSuchProviderException, XMLParserException, UnmarshallingException, MarshallingException,
    SignatureException, TransformerFactoryConfigurationError, TransformerException, ErrorCodeException,
    InitializationException, ComponentInitializationException
  {
    String issuer = "https://test/";
    String destination = "test destination";
    String providerName = "test providername";
    EidasNameIdType nameIdPolicy = EidasNameIdType.PERSISTENT;
    EidasLoaEnum loa = EidasLoaEnum.LOA_LOW;
    List<X509Certificate> authors = new ArrayList<>();

    X509Certificate cert = Utils.readCert(TestEidasSaml.class.getResourceAsStream("/EidasSignerTest_x509.cer"));
    authors.add(cert);
    PrivateKey pk = Utils.readPKCS12(TestEidasSaml.class.getResourceAsStream(TEST_P12), "123456".toCharArray())
                         .getKey();
    EidasSigner signer = new EidasSigner(pk, cert);

    AuthnRequest authnRequest = buildAuthnRequest(requestedAttributes);

    byte[] request = EidasSaml.createRequest(issuer,
                                             destination,
                                             providerName,
                                             null,
                                             signer,
                                             requestedAttributes,
                                             null,
                                             nameIdPolicy,
                                             loa);
    String resultStr = new String(org.bouncycastle.util.encoders.Base64.encode(request), StandardCharsets.UTF_8);
    System.out.println("--->" + resultStr);
    EidasRequest result = EidasSaml.parseRequest(new ByteArrayInputStream(request), authors);
    AuthnRequest createdRequest = result.getAuthnRequest();
    Assertions.assertEquals(issuer, result.getIssuer());
    Assertions.assertEquals(destination, result.getDestination());
    Assertions.assertEquals(providerName, result.getProviderName());
    Assertions.assertEquals(destination, result.getDestination());
    Assertions.assertEquals(loa, result.getAuthClassRef());
    Assertions.assertEquals(authnRequest.isForceAuthn(), createdRequest.isForceAuthn());
    Assertions.assertEquals(authnRequest.isPassive(), createdRequest.isPassive());
    Assertions.assertEquals(requestedAttributes.size(), result.getRequestedAttributesEntries().size());
    Assertions.assertNull(createdRequest.getScoping());
    Assertions.assertEquals(authnRequest.getExtensions().getUnknownXMLObjects().size(),
                            createdRequest.getExtensions().getUnknownXMLObjects().size());
    Assertions.assertEquals(authnRequest.getExtensions().getUnknownXMLObjects().get(0).getOrderedChildren().size(),
                            createdRequest.getExtensions().getUnknownXMLObjects().get(0).getOrderedChildren().size());
    for ( Map.Entry<EidasPersonAttributes, Boolean> entry : result.getRequestedAttributesEntries() )
    {
      Assertions.assertEquals(requestedAttributes.get(entry.getKey()), entry.getValue());
    }
  }

  @Test
  void requestFromXMLfile() throws IOException, CertificateException, XMLParserException, UnmarshallingException,
    ErrorCodeException, InitializationException, ComponentInitializationException
  {
    String issuer = "https://test/";
    String destination = "test destination";
    String providerName = "test providername";
    X509Certificate cert = Utils.readCert(TestEidasSaml.class.getResourceAsStream("/EidasSignerTest_x509-old.cer"));
    List<X509Certificate> authors = new ArrayList<>();
    authors.add(cert);


    byte[] request = Files.readAllBytes(Paths.get("src/test/resources/EidasSamlRequest_13062017.xml"));


    EidasRequest result = EidasSaml.parseRequest(new ByteArrayInputStream(request), authors);
    Assertions.assertEquals(issuer, result.getIssuer());
    Assertions.assertEquals(destination, result.getDestination());
    Assertions.assertEquals(providerName, result.getProviderName());
    Assertions.assertEquals(destination, result.getDestination());
    Assertions.assertEquals(requestedAttributes.size(), result.getRequestedAttributesEntries().size());
    for ( Map.Entry<EidasPersonAttributes, Boolean> entry : result.getRequestedAttributesEntries() )
    {
      Assertions.assertEquals(requestedAttributes.get(entry.getKey()), entry.getValue());
    }
  }

  @Test
  void createParseResponse() throws CertificateException, IOException, UnrecoverableKeyException, KeyStoreException,
    NoSuchAlgorithmException, NoSuchProviderException, KeyException, XMLParserException, UnmarshallingException,
    EncryptionException, MarshallingException, SignatureException, TransformerFactoryConfigurationError,
    TransformerException, ErrorCodeException, InitializationException, ComponentInitializationException, SAXException
  {
    BirthNameAttribute birthName = new BirthNameAttribute("Meyer");
    CurrentAddressAttribute currentAddress = new CurrentAddressAttribute("bla", "bla", "bla", "bla", "Am Fallturm 33",
                                                                         "Bremen", "D", "HB", "28207");
    DateOfBirthAttribute dao = new DateOfBirthAttribute("1982-02-11");
    FamilyNameAttribute familyName = new FamilyNameAttribute("Muller", "Müller");
    GenderAttribute gender = new GenderAttribute(GenderType.MALE);
    GivenNameAttribute givenName = new GivenNameAttribute("Bjorn", "Bjørn");
    PersonIdentifierAttribute pi = new PersonIdentifierAttribute("test12321");
    PlaceOfBirthAttribute pob = new PlaceOfBirthAttribute("Saint-Étienne, France");
    ArrayList<EidasAttribute> att = new ArrayList<>();
    att.add(birthName);
    att.add(currentAddress);
    att.add(dao);
    att.add(familyName);
    att.add(gender);
    att.add(givenName);
    att.add(pi);
    att.add(pob);

    String destination = "test destination";
    String recipient = "test_recipient";
    EidasNameId nameid = new EidasPersistentNameId("eidasnameidTest");
    String issuer = "test issuer";
    String inResponseTo = "_inResponseTo";
    EidasLoaEnum loa = EidasLoaEnum.LOA_SUBSTANTIAL;
    X509Certificate[] cert = {Utils.readCert(TestEidasSaml.class.getResourceAsStream("/EidasSignerTest_x509.cer"))};
    X509KeyPair[] keypair = {Utils.readPKCS12(TestEidasSaml.class.getResourceAsStream(TEST_P12),
                                              "123456".toCharArray())};
    PrivateKey pk = keypair[0].getKey();
    EidasEncrypter encrypter = new EidasEncrypter(true, cert[0],
                                                  List.of(new EncryptionAlgorithmInfo(EidasEncrypter.DEFAULT_ALGO_KEYTRANSPORT)));
    EidasSigner signer = new EidasSigner(true, pk, cert[0]);

    byte[] response = EidasSaml.createResponse(att,
                                               destination,
                                               recipient,
                                               nameid,
                                               issuer,
                                               loa,
                                               inResponseTo,
                                               encrypter,
                                               signer);
    System.out.println("-->>Response-->>" + new String(response));

    // This method can validate responses as well
    EidasSaml.validateXMLRequest(new ByteArrayInputStream(response), false);

    EidasResponse result = EidasResponse.parse(new ByteArrayInputStream(response), keypair, cert);

    Assertions.assertEquals(destination, result.getDestination());
    Assertions.assertEquals(nameid.getValue(), result.getNameId().getValue());
    Assertions.assertEquals(issuer, result.getIssuer());
    Assertions.assertEquals(inResponseTo, result.getInResponseTo());
    for ( int i = 0 ; i < att.size() ; i++ )
    {
      Assertions.assertEquals(att.get(i), result.getAttributes().get(i));
    }
  }

  @Test
  void createParseErrorResponse() throws CertificateException, IOException, UnrecoverableKeyException,
    KeyStoreException, NoSuchAlgorithmException, NoSuchProviderException, KeyException, XMLParserException,
    UnmarshallingException, MarshallingException, SignatureException, TransformerFactoryConfigurationError,
    TransformerException, ErrorCodeException, ComponentInitializationException, SAXException
  {
    String destination = "test destination";
    String recipient = "test_recipient";
    EidasNameId nameid = new EidasPersistentNameId("eidasnameidTest");
    String issuer = "test issuer";
    String inResponseTo = "_inResponseTo";
    EidasLoaEnum loa = EidasLoaEnum.LOA_SUBSTANTIAL;
    X509Certificate[] cert = {Utils.readCert(TestEidasSaml.class.getResourceAsStream("/EidasSignerTest_x509.cer"))};
    X509KeyPair[] keypair = {Utils.readPKCS12(TestEidasSaml.class.getResourceAsStream(TEST_P12),
                                              "123456".toCharArray())};
    PrivateKey pk = keypair[0].getKey();
    EidasEncrypter encrypter = new EidasEncrypter(true, cert[0],
                                                  List.of(new EncryptionAlgorithmInfo(EidasEncrypter.DEFAULT_ALGO_KEYTRANSPORT)));
    EidasSigner signer = new EidasSigner(true, pk, cert[0]);

    byte[] response = new EidasResponse(destination, recipient, nameid, inResponseTo, issuer, loa, signer,
                                        encrypter).generateErrorRsp(ErrorCode.AUTHORIZATION_FAILED, "Cancel!");

    // This method can validate responses as well
    EidasSaml.validateXMLRequest(new ByteArrayInputStream(response), false);

    EidasResponse result = EidasResponse.parse(new ByteArrayInputStream(response), keypair, cert);

    Assertions.assertEquals(destination, result.getDestination());
    Assertions.assertEquals(StatusCode.AUTHN_FAILED,
                            result.getOpenSamlResponse().getStatus().getStatusCode().getStatusCode().getValue());
    Assertions.assertEquals(issuer, result.getIssuer());
    Assertions.assertEquals(inResponseTo, result.getInResponseTo());
  }

  @Test
  void createParseMetaDataService() throws IOException, XMLParserException, UnmarshallingException,
    MarshallingException, SignatureException, TransformerFactoryConfigurationError, TransformerException,
    CertificateException, UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException,
    NoSuchProviderException, InitializationException, ComponentInitializationException, ErrorCodeException
  {
    String id = "test id";
    String entityId = "test entityid";
    String middlewareVersion = "1.2";
    Instant validUntil = Instant.parse("2025-01-01T00:00:00Z");

    X509Certificate sigCert = Utils.readCert(TestEidasSaml.class.getResourceAsStream("/EidasSignerTest_x509.cer"));
    X509Certificate encCert = Utils.readCert(TestEidasSaml.class.getResourceAsStream("/EidasSignerTest_x509.cer"));
    EidasOrganisation organisation = new EidasOrganisation("eidas orga", "EIDAS LLC", "http://www.example.com", "en");
    EidasContactPerson technicalcontact = new EidasContactPerson("technical company", "Michelle", "Obama", "0123456789",
                                                                 "technical@example.com", "technical");
    EidasContactPerson supportContact = new EidasContactPerson("support  company", "Barack", "Obama", "789",
                                                               "support@example.com", "support");
    String postEndpoint = "post.eu/endpoint";
    String redirectEndpoint = "redirect.eu/endpoint";
    List<EidasNameIdType> supportedNameIdTypes = new ArrayList<>();
    supportedNameIdTypes.add(EidasNameIdType.PERSISTENT);
    supportedNameIdTypes.add(EidasNameIdType.TRANSIENT);
    List<EidasPersonAttributes> attributes = new ArrayList<>();
    attributes.add(EidasNaturalPersonAttributes.BIRTH_NAME);
    attributes.add(EidasNaturalPersonAttributes.CURRENT_ADDRESS);
    attributes.add(EidasNaturalPersonAttributes.DATE_OF_BIRTH);
    attributes.add(EidasNaturalPersonAttributes.FAMILY_NAME);
    attributes.add(EidasNaturalPersonAttributes.FIRST_NAME);
    attributes.add(EidasNaturalPersonAttributes.GENDER);
    attributes.add(EidasNaturalPersonAttributes.PERSON_IDENTIFIER);
    attributes.add(EidasNaturalPersonAttributes.PLACE_OF_BIRTH);

    PrivateKey pk = Utils.readPKCS12(TestEidasSaml.class.getResourceAsStream(TEST_P12), "123456".toCharArray())
                         .getKey();
    EidasSigner signer = new EidasSigner(pk, sigCert);


    byte[] mds = EidasSaml.createMetaDataService(id,
                                                 entityId,
                                                 validUntil,
                                                 sigCert,
                                                 encCert,
                                                 organisation,
                                                 technicalcontact,
                                                 supportContact,
                                                 postEndpoint,
                                                 redirectEndpoint,
                                                 supportedNameIdTypes,
                                                 attributes,
                                                 signer,
                                                 middlewareVersion,
                                                 true,
                                                 true,
                                                 "DE");
    EidasMetadataService emds = EidasSaml.parseMetaDataService(new ByteArrayInputStream(mds));
    Assertions.assertEquals(encCert, emds.getEncCert());
    Assertions.assertEquals(entityId, emds.getEntityId());
    Assertions.assertEquals(id, emds.getId());
    Assertions.assertEquals(middlewareVersion, emds.getMiddlewareVersion());
    Assertions.assertEquals(organisation.getName(), emds.getOrganisation().getName());
    Assertions.assertEquals(organisation.getDisplayName(), emds.getOrganisation().getDisplayName());
    Assertions.assertEquals(organisation.getLangId(), emds.getOrganisation().getLangId());
    Assertions.assertEquals(organisation.getUrl(), emds.getOrganisation().getUrl());
    Assertions.assertEquals(postEndpoint, emds.getPostEndpoint());
    Assertions.assertEquals(redirectEndpoint, emds.getRedirectEndpoint());
    Assertions.assertEquals(sigCert, emds.getSigCert());
    Assertions.assertEquals(supportContact.getCompany(), emds.getSupportContact().getCompany());
    Assertions.assertEquals(supportContact.getEmail(), emds.getSupportContact().getEmail());
    Assertions.assertEquals(supportContact.getGivenName(), emds.getSupportContact().getGivenName());
    Assertions.assertEquals(supportContact.getSurName(), emds.getSupportContact().getSurName());
    Assertions.assertEquals(supportContact.getTel(), emds.getSupportContact().getTel());
    Assertions.assertEquals(supportContact.getType(), emds.getSupportContact().getType());
    Assertions.assertEquals(technicalcontact.getCompany(), emds.getTechnicalContact().getCompany());
    Assertions.assertEquals(technicalcontact.getEmail(), emds.getTechnicalContact().getEmail());
    Assertions.assertEquals(technicalcontact.getGivenName(), emds.getTechnicalContact().getGivenName());
    Assertions.assertEquals(technicalcontact.getSurName(), emds.getTechnicalContact().getSurName());
    Assertions.assertEquals(technicalcontact.getTel(), emds.getTechnicalContact().getTel());
    Assertions.assertEquals(technicalcontact.getType(), emds.getTechnicalContact().getType());
    Assertions.assertEquals(validUntil, emds.getValidUntil());
    Assertions.assertEquals(attributes.size(), emds.getAttributes().size());
    Assertions.assertEquals("DE", emds.getNodeCountry());
  }

  @Test
  void createTestRequestWithTestCase() throws Exception
  {
    String issuer = "issuer";
    String destination = "test destination";
    EidasNameIdType nameIdPolicy = EidasNameIdType.PERSISTENT;
    EidasLoaEnum loa = EidasLoaEnum.LOA_TEST;
    List<X509Certificate> authors = new ArrayList<>();

    X509Certificate cert = Utils.readCert(TestEidasSaml.class.getResourceAsStream("/EidasSignerTest_x509.cer"));
    authors.add(cert);
    PrivateKey pk = Utils.readPKCS12(TestEidasSaml.class.getResourceAsStream(TEST_P12), "123456".toCharArray())
                         .getKey();
    EidasSigner signer = new EidasSigner(pk, cert);

    AuthnRequest authnRequest = buildAuthnRequest(requestedAttributes);

    byte[] request = EidasSaml.createRequest(issuer,
                                             destination,
                                             signer,
                                             requestedAttributes,
                                             null,
                                             nameIdPolicy,
                                             loa,
                                             TestCaseEnum.UNKNOWN);
    String resultStr = new String(org.bouncycastle.util.encoders.Base64.encode(request), StandardCharsets.UTF_8);
    System.out.println("--->" + resultStr);
    EidasRequest result = EidasSaml.parseRequest(new ByteArrayInputStream(request), authors);
    AuthnRequest createdRequest = result.getAuthnRequest();
    Assertions.assertEquals(issuer, result.getIssuer());
    Assertions.assertEquals(destination, result.getDestination());
    Assertions.assertEquals(Constants.DEFAULT_PROVIDER_NAME, result.getProviderName());
    Assertions.assertEquals(destination, result.getDestination());
    Assertions.assertTrue(new String(request).contains(loa.getUri() + "#" + TestCaseEnum.UNKNOWN.getTestCase()));
    Assertions.assertEquals(authnRequest.isForceAuthn(), createdRequest.isForceAuthn());
    Assertions.assertEquals(authnRequest.isPassive(), createdRequest.isPassive());
    Assertions.assertEquals(requestedAttributes.size(), result.getRequestedAttributesEntries().size());
    Assertions.assertNull(createdRequest.getScoping());
    Assertions.assertEquals(authnRequest.getExtensions().getUnknownXMLObjects().size(),
                            createdRequest.getExtensions().getUnknownXMLObjects().size());
    Assertions.assertEquals(authnRequest.getExtensions().getUnknownXMLObjects().get(0).getOrderedChildren().size(),
                            createdRequest.getExtensions().getUnknownXMLObjects().get(0).getOrderedChildren().size());
    for ( Map.Entry<EidasPersonAttributes, Boolean> entry : result.getRequestedAttributesEntries() )
    {
      Assertions.assertEquals(requestedAttributes.get(entry.getKey()), entry.getValue());
    }
  }


  @SneakyThrows
  @Test
  void testMetadataParsingRsa()
  {
    EidasMetadataNode eidasMetadataNode = EidasSaml.parseMetaDataNode(new ByteArrayInputStream(METADATA_RSA_XML.getBytes(StandardCharsets.UTF_8)),
                                                                      null,
                                                                      true);
    Assertions.assertEquals(2, eidasMetadataNode.getSupportedEncryptionAlgorithms().size());
    EncryptionAlgorithmInfo encryptionAlgorithmInfo = eidasMetadataNode.getSupportedEncryptionAlgorithms().get(1);
    Assertions.assertEquals(EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSAOAEP11, encryptionAlgorithmInfo.getAlgorithm());
    Assertions.assertNull(encryptionAlgorithmInfo.getKeySize());
    Assertions.assertEquals(EncryptionConstants.ALGO_ID_DIGEST_SHA256, encryptionAlgorithmInfo.getDigestAlgorithm());
    Assertions.assertEquals(EncryptionConstants.ALGO_ID_MGF1_SHA256, encryptionAlgorithmInfo.getMgfAlgorithm());
  }

  @SneakyThrows
  @Test
  void testMetadataParsingEC()
  {
    EidasMetadataNode eidasMetadataNode = EidasSaml.parseMetaDataNode(new ByteArrayInputStream(METADATA_EC_XML.getBytes(StandardCharsets.UTF_8)),
                                                                      null,
                                                                      true);
    Assertions.assertEquals(3, eidasMetadataNode.getSupportedEncryptionAlgorithms().size());
    EncryptionAlgorithmInfo encryptionAlgorithmInfo = eidasMetadataNode.getSupportedEncryptionAlgorithms().get(2);
    Assertions.assertEquals(EncryptionConstants.ALGO_ID_KEYAGREEMENT_ECDH_ES, encryptionAlgorithmInfo.getAlgorithm());
    Assertions.assertNull(encryptionAlgorithmInfo.getKeySize());
    Assertions.assertNull(encryptionAlgorithmInfo.getDigestAlgorithm());
    Assertions.assertNull(encryptionAlgorithmInfo.getMgfAlgorithm());
    Assertions.assertEquals(EncryptionConstants.ALGO_ID_KEYDERIVATION_CONCATKDF,
                            encryptionAlgorithmInfo.getKdfParams().algorithm());
    Assertions.assertEquals(EncryptionConstants.ALGO_ID_DIGEST_SHA256, encryptionAlgorithmInfo.getKdfParams().digest());
    Assertions.assertEquals("NONCE", encryptionAlgorithmInfo.getKaNonceValue());


  }

  private AuthnRequest buildAuthnRequest(Map<EidasPersonAttributes, Boolean> requestedAttributes)
  {
    AuthnRequest authnRequest = new AuthnRequestBuilder().buildObject();
    authnRequest.setDestination("destination");
    authnRequest.setIsPassive(false);
    authnRequest.setForceAuthn(true);
    setRequesterId(authnRequest);
    setExtension(authnRequest, requestedAttributes);

    return authnRequest;
  }

  private void setExtension(AuthnRequest authnRequest, Map<EidasPersonAttributes, Boolean> requestedAttributes)
  {
    Extensions extensions = new ExtensionsBuilder().buildObject();
    XSAny requestedAttributeExtension = new XSAnyBuilder().buildObject(EIDAS_EXTENSION_NAMESPACE_URI,
                                                                       "RequestedAttributes",
                                                                       EIDAS);

    for ( Map.Entry<EidasPersonAttributes, Boolean> entry : requestedAttributes.entrySet() )
    {
      XSAny requestedAttribute = new XSAnyBuilder().buildObject(EIDAS_EXTENSION_NAMESPACE_URI,
                                                                "RequestedAttribute",
                                                                EIDAS);
      requestedAttribute.getUnknownAttributes().put(new QName(NAME), entry.getKey().getName());
      requestedAttribute.getUnknownAttributes()
                        .put(new QName(NAME_FORMAT), "urn:oasis:names:tc:SAML:2.0:attrname-format:uri");
      requestedAttribute.getUnknownAttributes().put(new QName("isRequired"), entry.getValue().toString());
      requestedAttributeExtension.getUnknownXMLObjects().add(requestedAttribute);

    }
    extensions.getUnknownXMLObjects().add(requestedAttributeExtension);
    authnRequest.setExtensions(extensions);
  }

  private void setRequesterId(AuthnRequest authnRequest)
  {
    Scoping scoping = new ScopingBuilder().buildObject();
    RequesterID requesterID = new RequesterIDBuilder().buildObject();
    requesterID.setURI("test requesterId");
    scoping.getRequesterIDs().add(requesterID);
    authnRequest.setScoping(scoping);
  }
}

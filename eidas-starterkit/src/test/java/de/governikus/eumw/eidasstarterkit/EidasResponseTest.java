package de.governikus.eumw.eidasstarterkit;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.core.impl.ResponseBuilder;

import de.governikus.eumw.eidascommon.ErrorCode;
import de.governikus.eumw.eidascommon.Utils;
import se.swedenconnect.opensaml.OpenSAMLInitializer;
import se.swedenconnect.opensaml.OpenSAMLSecurityDefaultsConfig;
import se.swedenconnect.opensaml.OpenSAMLSecurityExtensionConfig;
import se.swedenconnect.opensaml.xmlsec.config.SAML2IntSecurityConfiguration;


class EidasResponseTest
{
  @BeforeEach
  void setUp() throws Exception
  {
    OpenSAMLInitializer.getInstance()
                       .initialize(new OpenSAMLSecurityDefaultsConfig(new SAML2IntSecurityConfiguration()),
                                   new OpenSAMLSecurityExtensionConfig());
  }
  @Test
  void eidasSamlResponseHasSecondStatusCode() throws Exception
  {
    Response response = new ResponseBuilder().buildObject();
    Utils.X509KeyPair[] keypair = {Utils.readPKCS12(EidasResponseTest.class.getResourceAsStream("/eidassignertest_ec.p12"),
                                                    "123456".toCharArray())};
    PrivateKey pk = keypair[0].getKey();
    X509Certificate cert = keypair[0].getCert();
    EidasEncrypter encrypter = new EidasEncrypter(true, cert);
    EidasSigner signer = new EidasSigner(true, pk, cert);

    EidasResponse eidasResponse = new EidasResponse("destination", "recipient",
                                                    new EidasPersistentNameId("eidasnameidTest"),
                                                    "inResponseTo", "issuer", EidasLoaEnum.LOA_HIGH, signer,
                                                    encrypter);

    eidasResponse.setSamlStatusError(response, ErrorCode.CANCELLATION_BY_USER, null);
    Assertions.assertEquals(response.getStatus().getStatusCode().getValue(), StatusCode.RESPONDER);
    Assertions.assertEquals(response.getStatus().getStatusCode().getStatusCode().getValue(), StatusCode.AUTHN_FAILED);
    Assertions.assertNotNull(response.getStatus().getStatusCode().getStatusCode());
  }

  @Test
  void eidasSamlResponseHasOneStatusCode() throws Exception
  {
    Response response = new ResponseBuilder().buildObject();
    Utils.X509KeyPair[] keypair = {Utils.readPKCS12(EidasResponseTest.class.getResourceAsStream("/eidassignertest_ec.p12"),
                                                    "123456".toCharArray())};
    PrivateKey pk = keypair[0].getKey();
    X509Certificate cert = keypair[0].getCert();
    EidasEncrypter encrypter = new EidasEncrypter(true, cert);
    EidasSigner signer = new EidasSigner(true, pk, cert);

    EidasResponse eidasResponse = new EidasResponse("destination", "recipient",
                                                    new EidasPersistentNameId("eidasnameidTest"),
                                                    "inResponseTo", "issuer", EidasLoaEnum.LOA_HIGH, signer,
                                                    encrypter);

    eidasResponse.setSamlStatusError(response, ErrorCode.SUCCESS, null);
    Assertions.assertEquals(response.getStatus().getStatusCode().getValue(), StatusCode.SUCCESS);
    Assertions.assertNull(response.getStatus().getStatusCode().getStatusCode());
  }

}

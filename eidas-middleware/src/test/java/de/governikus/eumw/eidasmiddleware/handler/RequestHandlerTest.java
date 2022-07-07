/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.eidasmiddleware.handler;

import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.zip.DataFormatException;

import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactoryConfigurationError;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.xml.sax.SAXParseException;

import de.governikus.eumw.eidascommon.ErrorCodeException;
import de.governikus.eumw.eidascommon.HttpRedirectUtils;
import de.governikus.eumw.eidasmiddleware.ConfigHolder;
import de.governikus.eumw.eidasmiddleware.RequestProcessingException;
import de.governikus.eumw.eidasmiddleware.ServiceProviderConfig;
import de.governikus.eumw.eidasmiddleware.eid.RequestingServiceProvider;
import de.governikus.eumw.eidasmiddleware.repositories.RequestSessionRepository;
import de.governikus.eumw.eidasstarterkit.EidasLoaEnum;
import de.governikus.eumw.eidasstarterkit.EidasNameIdType;
import de.governikus.eumw.eidasstarterkit.EidasNaturalPersonAttributes;
import de.governikus.eumw.eidasstarterkit.EidasRequest;
import de.governikus.eumw.eidasstarterkit.EidasSaml;
import de.governikus.eumw.eidasstarterkit.EidasSigner;
import de.governikus.eumw.eidasstarterkit.person_attributes.EidasPersonAttributes;
import de.governikus.eumw.utils.key.KeyStoreSupporter;
import lombok.extern.slf4j.Slf4j;
import se.litsec.eidas.opensaml.ext.SPTypeEnumeration;


/**
 * Test the handling of incoming SAML requests
 */
@Slf4j
@ExtendWith(MockitoExtension.class)
@ExtendWith(SpringExtension.class)
class RequestHandlerTest
{

  @MockBean
  private RequestSessionRepository requestSessionRepository;

  @MockBean
  private ServiceProviderConfig mockServiceProviderConfig;

  @MockBean
  private ConfigHolder mockConfigHolder;

  private static final String RELAY_STATE = "State#1542107483529";

  private static final String GET_REQUEST = "1Vhbr+JGEn5OpPwHxEj7ghhfwGCzc07UvmLAxjZgLi8rY7cv+Irv+NevzYGTk2QmO1llpQ1CAldXff11VXW5q7/8XIdBr4Rp5sXRSx/7jPZ7MDJjy4ucl/5uyw/J/s+vXzIjDPBkBorcjTR4LWCW91rDKJu9jbz0izSaxUbmZbPICGE2y83ZBkirGf4ZnSVpnMdmHPQfNtCzjOyl7+Z5MkOQ+9NnWKRxYrQ/SIc4hHUOo45T1u+x7WxeZOR3hg+jIDaNwI2zfEaiJIpAkQUbFoYxSJLAM++6iAwrDZrQa1e3gWkZwLzf4+PUhPdlvPTztID9nsi+9P8Fz9OJjaHEEKNQOBzj9nlIjQ1sSIxGxpg0TGNq2K1qphhZ1uK99G0jyDrjLCugGGW5EeUvfRzFyCGGDbHRFsNm7RcffSZw6tTvKWlcehZM5dY3L30W2kYR5E9hv6c//d96q//w9uyOnX508x97uaUG027h91WGRv7H6p3Es4b2XXUGo9zLb/3XP+FeCeaGZeTGF+Qj39cvVjbbeE4bryKFD/bWL9GuqupzNfocpw6CoyiKoBTS6liZ53zqv/7049MaWmJkxw8BY0Rx1E4beM196nZmN7Z6IHDi1Mvd8BvgGIKhHXibTObQxMbRpz7yYYo7we+EmiIo8eQ5DOMUfspcAycmwzQzhpLAY+/IGrRh2u4g2Ntp4kv/0/el1sN4mxpR1kUk+63gPzL8lSdhVMIgTqA1zJ4LfSf4/ZDf8h/yNaas57Tb9Lsjg4475NZPD0e+03vD0Y2ggK/66VbSzIJCLkCcO1NksolrSPHjNc9gTShPTsmStdb+OaHHL3dWH40fRN/j8RT8Lrvec+Fptzf8LaYpxAg9SfAMakkHKYOrMKsDRdlAfHW8crIux/PGnIvCdR+sfHG3diJacSaiQ8abcUPVtqN70fr6j0/Y6J8//ThxvBvuMt7RnE/Icwl3wZlYTUawwV2DieaqBnfQrw8rgx23fmVZysN1fKnc7OUFF7ZxcATlSQ0xbLtcPiEb1LYR2ig23uiSTDcCkp8hc57q0WgRLXd0yolO7mfslKx8pclXxyV2yZfTwWjartzbxAfRZciTvIptEPgPSNtKVWE6p64y4/OjnU+pxc0vZfbg+/XZkbCwmLh0vkolz6DWlNwQAJkL9HmTIEpaq1wZKCdz3VRwPfW2D8jCbEry3FYO7oiwlxsReLdAm6zIjQCmyfJI7aIgHDkvLx+C86tYdAFawts9XN3/A4FSbFt03h+YrubZXU2Cr5IocvKFYUA9cUAl0sARRdlPB6Q1ks6KX7HqcbGMT6JbmjJQuRWtgkpvuEhidgLAdhyoKngMqaZFoUVBX2gMzZ5xLLf2RHLEedTYU0U7FpiR1kgaWc3VI6ur6pKlT54Z6vlpP3bOOJEZeyIQ553eqbXTG0nNKuZNV+CqBadtAeQrtJYagEtbrpa2UiOzvNHJ5EsnA+8ySUBrsQEu7cg6DSRJCBelecPQ00FGVwftYglU2s5bmDifn9ttYeytQtKcinfu861YQN11Wx43SwhCYy+7lrCr5w2w3jBjiQ8Xt9MeC84eXZ7DOjmHO8fs9MPgcjpINdOAxZvucQtCLWj9TIsXINOOf3V9T6AqlG79yQOwZoBKgm6ccZbtfw7kA2Ha+JrIrINbE/JjfWHQHrZNcXtdhWcjZcPGdThnKVmYqxJShVVWwi3wjXIVj2Po5at5inlKwYxClovZvcmigUFct3QcbRBF01fzzYJXgmx9GdviiUqPGLff6rxzGGzTU7Q2EkwliD2O40tBP+u1TbK6qB6ya2BDLYOZ4DRVEmeInlgoOZmORdo/4E05ZfaCJ7piqEDoJbHU8CM1reVFaAgXUqCu6yQFKOUgwsbz96GyU+Ng07BlduYahMSnhGDIS54ShNiw2VNMpQoZixVTua58jIqDj8+zpI54KjCD9CDY00iQZb3d8LGvmWgaqgWZzJsiFFNrzml1GRL7US2uF4c1R8MNnaxFtX0fq4COx/NSEueZBKoufy2u4mikUhkJgEqp2vhraECzTiU7R3FZHWla3c1BxQkMkwlA3fF0JTG046S0w/G0arJtfJd3PSAwcq0ywPnwXMUsywK7y4P5RuIEFuwdWuXFq08OlqqGbHJjPFpVJGE2+iKoLw1Y33VVkgY2ybW5y9Ar8LZnNHRN00eOXx6r06Ie4OuEN+FaHWTjawj3wPALTeKyDzw5mmbJStmC6Qe+FTgeS2OuoSYblyucupgjUHT7d7V/5jPhnzZUZe0X7Z6UR6e9WJojzbXmevPQ/1pNYB2npbuaE0iIhMZBdSYW62xZkxq0oV3uJWIPshNXmoMzIV95BIAbT8eTlDBNx1Ibf33dn/Us5iudPgUuqDFqEhybOF+428H66uBHWTOUWtHQmNkUh9oqd6jCmLhPFk3hu6sdbeWThpLJHXcl5fEG+tqWCCEzMi1aOWUstGCeZFbMHOxDeStWmsg2ZRgFNl0b/tKd728FNahZ9Ey0ywxxdCNIorLUed2jRtVVulm7IM/mR1vfw+nOG19bl8srIA+OwnxvjLzJtHRx7iRuRueypoKFvd6K47Tc5trBJDYTJVnuarfcY9noyC62zcB3NcRnD/Vxgx8mAqHM9UO6tENjhGFJkOQjhJT0o+sOEq4QeA19e0//tnC/C99KO/Kx6P/qtfDeiXDv/UH7kug9Pl/urcTs0aBAC+R56p2LHHZKP/zwwzfHe2/n8m80JMY7DHJnYQRJe15vT8BKYLRpa9Nemrv9O8b3HLw7uE76PHoXqdfveVnHykuh9ewtkNe/mi5TpO1JKBfaBibqEP5CyvdW6n/GmDdCL7j9PSgr9x/R6hoq2+uau/93xu2e+/slMbCsFGbZ34Dw3bF/ce4+uX4ofcgf1b43jd+Xzmc17YiJrBK3vf2tbd6CuGJS2KbF847kz98n5F1/6LWB6jz6mOUXbt39CxNHOazzHhOHiZF6WXf9EXqRFxZh/+PC3i4XPpowgZG1zrD/m6uR12+EbxUDxPUc93mZ8bX5fuvIr67n9X3442XZ678B";

  private static final String INVALID_BASE64 = "JIEn6e/hUlWtqXEu0DDDbbVaP0iQEb24A5XlbGTh/lEx/Y+NdvmqO6ZrZnpnc1K80gJMh0ZOSXXxzOiK8/N3H0dIZ5EaTJS4/4gveeYGKnTpB4L73NWuzTvZ9fvxZWHJHZBFSlnxjwVMGifEILk2Jye/LSq/JkklpFUEwSK4bFpLQnK6AsJuQXfJLlaZnaadS7r4GBYxUvPb8sswmGXUdfYJWnmYV+sE5jHzYlTDpMRe+JR7sFiVVeEd4XRaltRX5alBMap3EMyjxY8TBOQZZFgX2VxVRYG9CGATrdCubnCJa9JzHNbXg9xkuvzCvYe5L5l96/4HE8cgmc6hMMDvtD0j32maFF9KnBwBrSlm2NLReJFppVFEjfS8+1oqJbXBQVlJOitJLypUfiBN0niD4xWBPEBH3JwReKZA69Jy1Pz4EDcxVx89LjoWtVUfmY7D2ZD/4RW70725Or7vwjzb/PMoIG8+7g11PGFgL0e0bpzBQ4ffcqOoFJGZSX3ut/Qa8CS8uxSuvr1WLkHe/rV6eYrAIP2avK4R29883adV1/qQdf0tzDSBzHMZzBkCM5ReB97r1+eiyGjpy46W3MWUmaIJtGQXu1K9rXT50nEHlpHpR+/O4Tv1RNYATeqUauZPdtYph87mHfNrii+0FNYwynHiD7cZrDz4VvkdSonxdWX5FE4qHYgC7MUfTAp40hv/Q+/5hb3UCtcyspOmMUvxr/4UF/wSFMzjBKM+j0EaM3GzzQve/whxp/gzrsOzD5wEPR+YNEEhg+7IhEFN0pfGC7qTGtqIKv5uFyZrkZg70BeeqNsdEqbSAjDpciR7SxOjpkc95ZhseMHb587TB9XPzpOvNuCMRlN+788aNLvfvnbcdPWytcE4ZGDfCDAo+gUUyQc6QOiybStBUkF/uToJpqOm3tqSydttEilDdLL2E1byR7dLoatkzjemaQLE//+EwM/vlp5AUX0ueCvT0d0ccz3ERHajEawJb0LS6Z6gbcwLDZLSx+iOzO80xAmuRcu7jzN1Jap9EenA96TBDr+fyuscVdF2OtahUM3rLxSsLKI+SOYzMZzJL5hs0F2SvDgh/Tdai15WI/J97K+fh5MEaBFKzSnexz9EFdpC6IwhtG18l1aTxlTioXioNNyOjVJTyr/C4Mm6OnEHE18tlykSuBxSwZtaUANpXY4yrDtLzRhXOkHexlW8PlOFjfNFZ2e6aPKA0Le4x/u1BRcImM0YJeSWCczffMJonigffy8s0qVw+9W6ELgzm8XCO/+7+jcIZHCeZ9wHX5ze3SO3xVZFlQ3zgONCMP1DILPFlWw/yZdgbKUQtrXt/P5ulB9s+2CnRhweqgNlshUbiNBIiNAOoa7mOmRVpYWTJnBsfyR5IonS2V7UkRt7ZMhZ5FdmK0ikHXU33Pm7o+59lDYMdmedgOvSNJFdaWiuRpJ3dA68xW0Yuau8lKQj0TjDWAYo03SgtIZS00ylppVV60ujn1rZtD7nafUyS8kVvgs55qskBRpHh2ti8Eftip+GJnvDkSk6N9K5sUyyMKBmvrVIrh1aJ33W/BA+Yqi3BcHCmKra3qO9KmmbbAuelMFTGeXQ5bIjoG7PkYN9kx3nh2Jx9Hb4ed0nAtmN1k92sQGxHimZXfgMp64ckPA4mpcRbxKQKw5IBOg+45583RfwGUz9K4DQ2ZW0aXNhaH5sxiA2Kdk+6yjo9Wzset7wneXHEIX6eUmqidTJiRK+0k74cwKBfTnAi0ihvEvJDyW5vHI4s6rdk0WWGaYS6mq5moRcXybejKBybfE8J2bYre7nmdH5KllRE6RW1JkpxL5tFsXJo3ZX1XnCIXGgUsJK+ts7TAzMzB6dF4KLPhjmzPY24rBbIvxxqEQZYqrTjQ80adxZb0RkvMaZnlAGc8TFoF4TbWNnoarVr+XByFFqPJMSVZ6lxkJCm1XP6QMrlGp3LN1b6v7pNqF5LTImsSkYnsKN9J7jiRVNVEsZ6Gho3nsV7R2bStYjl3poLRnGNqO2jk5Wy3FFi4YrOlrKOrjQ7YdDg9K/K0UEDd+a8j1AKL1TqnAFBrNbK/gUcs79Wqt5fn9Z5l9c0U1ILEcYUE9I3I1grHel7OeoLI6jaP7Du/ygGJUxudA96HcZ3yPA/czg+mK0WQeLD1WF2UTyH9PNcNbFVaw8Gipim7NWdR89aC5VVWp1ng0gLyXY5dgFvMGPiSZfeCON/Xh1nzTC4z0YZL/bkYnmK4BVZYGYpQfMApsCxP19oajD/grcF+f7amBm7z6XlBMm/2AFRd/C62D3+mwsOKqZ3tDMWkOjhs5bM9MHxnarZ3+e/lBN7zENzFlMJiLLZ2ujdyeG/N28wzMu18q1BbUByEs/18pNSTiAFwEdl0lFO27Tl6Gy5P26NZpGJtsofIBw3BjKJ9m5Yzf/28PHnkXjUsrdEMPOVW1a5xzhtc42wypKu2Cv3FhnXKUcuo9EY40epwBUNjTcWQG9gOqx0KHjqwzAon5Xbu7nypFobMt+c4iVy2scK5P91eKua54fEjhY4Zk/hKUmRtbopmwAzqk3JxNlFZTPeuuYXjTTA8IcrVBVCf99J0aw2C0fjsk8JBXg2O54aJZu5yLQ/z87o0dja1GmnZfNP45y1RDPb8bN0+h76Bhfyu2a/I3UiitKm5y+dubA0IIouycoDRirn3/edMqCTRwG9v5y6Lf0zc75O31N6JvCf9x7v6+lZ4rzqE91rg9dPT/fP1WjVMVtr6ksHXrDqiW//XWynxmPy17L1ugQ4oyzw4ViVEV62ffvrpruo/Hz/dbuu/UaZY71qw6z3LijJ0i0dlhxZZyMFdNshLv3fV8SPX8U5ddyV/XMirPOg9BUWHKsih86g4sNc/Gy5X5ejOWkqorEk6sH8i5GuB9X9DLFpxEF3+HpC1q2vITldmuQHM//oko+j8+zkxcJwcFqhl8JePumt2+JN999aTQEXue5K8J8TvZr5O6F66Z5MPKfbR6+nAybyWosR6QRVjlNZcDpFTPPomP5LUftljKLsSN0Ah0OWEe0fpG7SuJ8OlSYk6P09cGmdWHqCQeenFQRLEVYyaA+/HuvUbrl2c+wouQt0PVPX9L92SR8/j132oRQowP/D8R3/je/vdQL3T+N3ToHfcd9pnr/8G";

  private static final String INVALID_SIGNED_XML = "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";

  private static final String DEFAULT_PASSWORD = "123456";


  /**
   * Add BC provider and prepare mockServiceProvderConfig to return the necessary SAML signature cert
   */
  @BeforeEach
  public void setUp() throws URISyntaxException
  {
    Security.addProvider(new BouncyCastleProvider());
    RequestingServiceProvider sp = new RequestingServiceProvider("http://localhost:8080/eIDASDemoApplication/Metadata");

    File keystoreFile = new File(RequestHandlerTest.class.getResource("/de/governikus/eumw/eidasmiddleware/bos-test-tctoken.saml-sign.p12")
                                                         .toURI());
    KeyStore signatureKeystore = KeyStoreSupporter.readKeyStore(keystoreFile, DEFAULT_PASSWORD);
    sp.setSignatureCert((X509Certificate)KeyStoreSupporter.getCertificate(signatureKeystore,
                                                                          "bos-test-tctoken.saml-sign")
                                                          .get());
    sp.setSectorType(SPTypeEnumeration.PUBLIC);
    Mockito.when(mockServiceProviderConfig.getProviderByEntityID("http://localhost:8080/eIDASDemoApplication/Metadata"))
           .thenReturn(sp);
  }

  /**
   * Test various requests with null or empty string parameters
   */
  @Test
  void testMissingParameters()
  {
    // both parameters null with POST
    RequestHandler requestHandler = new RequestHandler(requestSessionRepository, mockConfigHolder,
                                                       mockServiceProviderConfig);
    RequestProcessingException requestProcessingException = Assertions.assertThrows(RequestProcessingException.class,
                                                                                    () -> requestHandler.handleSAMLRequest(null,
                                                                                                                           null,
                                                                                                                           true));
    Assertions.assertEquals(requestProcessingException.getCause().getClass(), ErrorCodeException.class);

    // both parameters null with GET
    requestProcessingException = Assertions.assertThrows(RequestProcessingException.class,
                                                         () -> requestHandler.handleSAMLRequest(null, null, false));
    Assertions.assertEquals(requestProcessingException.getCause().getClass(), ErrorCodeException.class);

    // saml request null with POST
    requestProcessingException = Assertions.assertThrows(RequestProcessingException.class,
                                                         () -> requestHandler.handleSAMLRequest(RELAY_STATE,
                                                                                                null,
                                                                                                true));
    Assertions.assertEquals(requestProcessingException.getCause().getClass(), ErrorCodeException.class);

    // saml request null with GET
    requestProcessingException = Assertions.assertThrows(RequestProcessingException.class,
                                                         () -> requestHandler.handleSAMLRequest(RELAY_STATE,
                                                                                                null,
                                                                                                false));
    Assertions.assertEquals(requestProcessingException.getCause().getClass(), ErrorCodeException.class);

    // both parameters emtpy String with POST
    requestProcessingException = Assertions.assertThrows(RequestProcessingException.class,
                                                         () -> requestHandler.handleSAMLRequest("", "", true));
    Assertions.assertEquals(requestProcessingException.getCause().getClass(), SAXParseException.class);

    // both parameters emtpy String with GET
    requestProcessingException = Assertions.assertThrows(RequestProcessingException.class,
                                                         () -> requestHandler.handleSAMLRequest("", "", false));
    Assertions.assertEquals(requestProcessingException.getCause().getClass(), SAXParseException.class);

    // saml request emtpy String with POST
    requestProcessingException = Assertions.assertThrows(RequestProcessingException.class,
                                                         () -> requestHandler.handleSAMLRequest(RELAY_STATE, "", true));
    Assertions.assertEquals(requestProcessingException.getCause().getClass(), SAXParseException.class);

    // saml request emtpy String with GET
    requestProcessingException = Assertions.assertThrows(RequestProcessingException.class,
                                                         () -> requestHandler.handleSAMLRequest(RELAY_STATE,
                                                                                                "",
                                                                                                false));
    Assertions.assertEquals(requestProcessingException.getCause().getClass(), SAXParseException.class);
  }

  /**
   * Test that a request with the wrong signature certificate is rejected
   */
  @Test
  void testWrongSignatureCertificate() throws URISyntaxException
  {
    // load the wrong certificate
    RequestingServiceProvider sp = new RequestingServiceProvider("http://localhost:8080/eIDASDemoApplication/Metadata");

    URL resource = RequestHandlerTest.class.getResource("/de/governikus/eumw/eidasmiddleware/bos-test-tctoken.saml-encr.p12");
    File keystoreFile = new File(resource.toURI());
    KeyStore signatureKeystore = KeyStoreSupporter.readKeyStore(keystoreFile, DEFAULT_PASSWORD);
    sp.setSignatureCert((X509Certificate)KeyStoreSupporter.getCertificate(signatureKeystore,
                                                                          "bos-test-tctoken.saml-encr")
                                                          .get());
    Mockito.when(mockServiceProviderConfig.getProviderByEntityID("http://localhost:8080/eIDASDemoApplication/Metadata"))
           .thenReturn(sp);

    // create the handler and process the rquest with the wrong signature
    RequestHandler requestHandler = new RequestHandler(requestSessionRepository, mockConfigHolder,
                                                       mockServiceProviderConfig);
    RequestProcessingException requestProcessingException = Assertions.assertThrows(RequestProcessingException.class,
                                                                                    () -> requestHandler.handleSAMLRequest(RELAY_STATE,
                                                                                                                           GET_REQUEST,
                                                                                                                           false));
    Assertions.assertEquals(requestProcessingException.getCause().getClass(),
                            ErrorCodeException.class,
                            "ErrorCodeException expected as cause");
    Assertions.assertEquals(RequestHandler.CANNOT_PARSE_SAML_REQUEST, requestProcessingException.getMessage());
  }

  /**
   * Test that a changed digest value is rejected
   */
  @Test
  void testManipulatedXML()
  {
    // In this request some xml values were changed after the signature was added
    String wrongDigest = "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";
    RequestHandler requestHandler = new RequestHandler(requestSessionRepository, mockConfigHolder,
                                                       mockServiceProviderConfig);
    RequestProcessingException requestProcessingException = Assertions.assertThrows(RequestProcessingException.class,
                                                                                    () -> requestHandler.handleSAMLRequest(RELAY_STATE,
                                                                                                                           wrongDigest,
                                                                                                                           false));
    Assertions.assertEquals(ErrorCodeException.class,
                            requestProcessingException.getCause().getClass(),
                            "ErrorCodeException expected as cause");
    Assertions.assertEquals(RequestHandler.CANNOT_PARSE_SAML_REQUEST, requestProcessingException.getMessage());
  }

  /**
   * Test that a correct request via GET is accepted
   */
  @Test
  void testGeneratedRequest() throws Exception
  {
    RequestHandler requestHandler = new RequestHandler(requestSessionRepository, mockConfigHolder,
                                                       mockServiceProviderConfig);
    File keystoreFile = new File(RequestHandlerTest.class.getResource("/de/governikus/eumw/eidasmiddleware/bos-test-tctoken.saml-sign.p12")
                                                         .toURI());
    KeyStore keyStore = KeyStoreSupporter.readKeyStore(keystoreFile, DEFAULT_PASSWORD);
    String request = createSAMLRequest(keyStore,
                                       DEFAULT_PASSWORD,
                                       "bos-test-tctoken.saml-sign",
                                       "http://localhost:8080/eIDASDemoApplication/Metadata",
                                       "http://localhost:8080/eIDASDemoApplication/NewReceiverServlet",
                                       EidasLoaEnum.LOA_HIGH);
    EidasRequest eidasRequest = requestHandler.handleSAMLRequest(RELAY_STATE, request, false);
    Assertions.assertNotNull(eidasRequest);
  }

  /**
   * Test that a correct request without RelayState via GET is accepted
   */
  @Test
  void testGeneratedRequestWithoutRelayState() throws Exception
  {
    RequestHandler requestHandler = new RequestHandler(requestSessionRepository, mockConfigHolder,
                                                       mockServiceProviderConfig);
    File keystoreFile = new File(RequestHandlerTest.class.getResource("/de/governikus/eumw/eidasmiddleware/bos-test-tctoken.saml-sign.p12")
                                                         .toURI());
    KeyStore keyStore = KeyStoreSupporter.readKeyStore(keystoreFile, DEFAULT_PASSWORD);
    String request = createSAMLRequest(keyStore,
                                       DEFAULT_PASSWORD,
                                       "bos-test-tctoken.saml-sign",
                                       "http://localhost:8080/eIDASDemoApplication/Metadata",
                                       "http://localhost:8080/eIDASDemoApplication/NewReceiverServlet",
                                       EidasLoaEnum.LOA_HIGH);
    EidasRequest eidasRequest = requestHandler.handleSAMLRequest(request, false);
    Assertions.assertNotNull(eidasRequest);
  }

  /**
   * Test that a request containing a wrong issuer is rejected
   */
  @Test
  void testWrongIssuer() throws URISyntaxException
  {
    RequestHandler requestHandler = new RequestHandler(requestSessionRepository, mockConfigHolder,
                                                       mockServiceProviderConfig);
    File keystoreFile = new File(RequestHandlerTest.class.getResource("/de/governikus/eumw/eidasmiddleware/bos-test-tctoken.saml-sign.p12")
                                                         .toURI());
    KeyStore keyStore = KeyStoreSupporter.readKeyStore(keystoreFile, DEFAULT_PASSWORD);
    String wrongIssuer = "http://wronghost:8080/eIDASDemoApplication/Metadata";
    String request = createSAMLRequest(keyStore,
                                       DEFAULT_PASSWORD,
                                       "bos-test-tctoken.saml-sign",
                                       wrongIssuer,
                                       "http://localhost:8080/eIDASDemoApplication/NewReceiverServlet",
                                       EidasLoaEnum.LOA_HIGH);

    RequestProcessingException requestProcessingException = Assertions.assertThrows(RequestProcessingException.class,
                                                                                    () -> requestHandler.handleSAMLRequest(RELAY_STATE,
                                                                                                                           request,
                                                                                                                           false));
    Assertions.assertEquals(ErrorCodeException.class,
                            requestProcessingException.getCause().getClass(),
                            "ErrorCodeException expected as cause");
    Assertions.assertEquals(RequestHandler.CANNOT_PARSE_SAML_REQUEST, requestProcessingException.getMessage());
  }

  /**
   * Test that a malformed base64 SAML request is rejected
   */
  @Test
  void testInvalidBase64()
  {
    RequestHandler requestHandler = new RequestHandler(requestSessionRepository, mockConfigHolder,
                                                       mockServiceProviderConfig);
    RequestProcessingException requestProcessingException = Assertions.assertThrows(RequestProcessingException.class,
                                                                                    () -> requestHandler.handleSAMLRequest(RELAY_STATE,
                                                                                                                           INVALID_BASE64,
                                                                                                                           false));
    Assertions.assertEquals(DataFormatException.class,
                            requestProcessingException.getCause().getClass(),
                            "ErrorCodeException expected as cause");
    Assertions.assertEquals(RequestHandler.CANNOT_PARSE_SAML_REQUEST, requestProcessingException.getMessage());
  }

  /**
   * Test a request with invalid XML is rejected
   */
  @Test
  void testInvalidXML()
  {
    RequestHandler requestHandler = new RequestHandler(requestSessionRepository, mockConfigHolder,
                                                       mockServiceProviderConfig);
    RequestProcessingException requestProcessingException = Assertions.assertThrows(RequestProcessingException.class,
                                                                                    () -> requestHandler.handleSAMLRequest(RELAY_STATE,
                                                                                                                           INVALID_SIGNED_XML,
                                                                                                                           false));
    Assertions.assertEquals(SAXParseException.class,
                            requestProcessingException.getCause().getClass(),
                            "ErrorCodeException expected as cause");
    Assertions.assertEquals(RequestHandler.CANNOT_PARSE_SAML_REQUEST, requestProcessingException.getMessage());
  }

  /**
   * Create a SAML request that is ready to be send via GET
   *
   * @param signKeystore the keystore that should be used to sign the request
   * @param password the password for the keystore
   * @param alias the alias for the keystore
   * @param issuerUrl The issuerURL for this request
   * @param destinationUrl the destinationURL for this request
   * @return The saml reqest as base54 and deflated to be send via GET
   */
  private String createSAMLRequest(KeyStore signKeystore,
                                   String password,
                                   String alias,
                                   String issuerUrl,
                                   String destinationUrl,
                                   EidasLoaEnum loA)
  {
    byte[] samlRequest;

    HashMap<EidasPersonAttributes, Boolean> reqAtt = new HashMap<>();
    reqAtt.put(EidasNaturalPersonAttributes.FIRST_NAME, true);
    reqAtt.put(EidasNaturalPersonAttributes.FAMILY_NAME, true);
    reqAtt.put(EidasNaturalPersonAttributes.PERSON_IDENTIFIER, true);
    reqAtt.put(EidasNaturalPersonAttributes.BIRTH_NAME, false);
    reqAtt.put(EidasNaturalPersonAttributes.PLACE_OF_BIRTH, false);
    reqAtt.put(EidasNaturalPersonAttributes.DATE_OF_BIRTH, false);
    reqAtt.put(EidasNaturalPersonAttributes.CURRENT_ADDRESS, false);

    try
    {
      EidasSaml.init();
      EidasSigner signer = new EidasSigner(true, (PrivateKey)signKeystore.getKey(alias, password.toCharArray()),
                                           (X509Certificate)signKeystore.getCertificate(alias));

      samlRequest = EidasSaml.createRequest(issuerUrl,
                                            destinationUrl,
                                            signer,
                                            reqAtt,
                                            null,
                                            EidasNameIdType.TRANSIENT,
                                            loA);
    }
    catch (CertificateEncodingException | InitializationException | MarshallingException | SignatureException
      | TransformerFactoryConfigurationError | TransformerException | IOException | UnrecoverableKeyException
      | NoSuchAlgorithmException | KeyStoreException e)
    {
      log.error("Can not create Request", e);
      return null;
    }

    return HttpRedirectUtils.deflate(samlRequest);
  }
}

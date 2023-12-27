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
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Optional;

import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactoryConfigurationError;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import de.governikus.eumw.config.EidasMiddlewareConfig;
import de.governikus.eumw.config.ServiceProviderType;
import de.governikus.eumw.eidascommon.ErrorCodeWithResponseException;
import de.governikus.eumw.eidasmiddleware.eid.RequestingServiceProvider;
import de.governikus.eumw.eidasmiddleware.repositories.RequestSessionRepository;
import de.governikus.eumw.eidasstarterkit.EidasLoaEnum;
import de.governikus.eumw.eidasstarterkit.EidasNameIdType;
import de.governikus.eumw.eidasstarterkit.EidasNaturalPersonAttributes;
import de.governikus.eumw.eidasstarterkit.EidasRequest;
import de.governikus.eumw.eidasstarterkit.EidasSaml;
import de.governikus.eumw.eidasstarterkit.EidasSigner;
import de.governikus.eumw.eidasstarterkit.person_attributes.EidasPersonAttributes;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationService;
import de.governikus.eumw.utils.key.KeyStoreSupporter;
import lombok.AllArgsConstructor;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.opensaml.eidas.ext.SPTypeEnumeration;


@Slf4j
@ExtendWith(MockitoExtension.class)
@ExtendWith(SpringExtension.class)
class RequestHandlerMatrixTest
{

  private static final String PROVIDER_NAME = "providerName";

  private static final String SERVICE_PROVIDER = "providerA";

  private static final String UNKNOWN_SERVICE_PROVIDER = "providerB";

  private static final String DEFAULT_PASSWORD = "123456";

  @MockBean
  private RequestSessionRepository requestSessionRepository;

  @MockBean
  private ConfigurationService mockConfigurationService;


  public static List<TestPrerequisites> testValidRequest()
  {
    List<TestPrerequisites> testData = new ArrayList<>();
    addTestCase(testData, null, SPTypeEnumeration.PUBLIC, null);
    addTestCase(testData, SERVICE_PROVIDER, SPTypeEnumeration.PUBLIC, null);
    addTestCase(testData, SERVICE_PROVIDER, SPTypeEnumeration.PRIVATE, null);
    addTestCase(testData, null, null, SPTypeEnumeration.PUBLIC);
    addTestCase(testData, SERVICE_PROVIDER, null, SPTypeEnumeration.PUBLIC);
    addTestCase(testData, SERVICE_PROVIDER, null, SPTypeEnumeration.PRIVATE);
    return testData;
  }

  public static List<TestPrerequisites> testInvalidRequest()
  {
    List<TestPrerequisites> testData = new ArrayList<>();
    addTestCase(testData, null, SPTypeEnumeration.PUBLIC, SPTypeEnumeration.PUBLIC);
    addTestCase(testData, null, SPTypeEnumeration.PUBLIC, SPTypeEnumeration.PRIVATE);
    addTestCase(testData, null, SPTypeEnumeration.PRIVATE, SPTypeEnumeration.PUBLIC);
    addTestCase(testData, null, SPTypeEnumeration.PRIVATE, SPTypeEnumeration.PRIVATE);
    addTestCase(testData, UNKNOWN_SERVICE_PROVIDER, SPTypeEnumeration.PRIVATE, null);
    addTestCase(testData, UNKNOWN_SERVICE_PROVIDER, null, SPTypeEnumeration.PRIVATE);
    addTestCase(testData, null, null, null);
    addTestCase(testData, SERVICE_PROVIDER, null, null);
    return testData;
  }

  private static void addTestCase(List<TestPrerequisites> testList,
                                  String requesterId,
                                  SPTypeEnumeration spTypeMetadata,
                                  SPTypeEnumeration spTypeRequest)
  {
    testList.add(new TestPrerequisites(null, requesterId, spTypeMetadata, spTypeRequest));
    testList.add(new TestPrerequisites(PROVIDER_NAME, requesterId, spTypeMetadata, spTypeRequest));
  }

  @ParameterizedTest
  @MethodSource
  void testValidRequest(TestPrerequisites testPrerequisites) throws URISyntaxException, ErrorCodeWithResponseException
  {
    log.info("TestPrerequisites for this test run: {}", testPrerequisites);
    prepareServiceProviderMock(testPrerequisites.spTypeMetadata);
    prepareConfig();

    String samlRequest = createSAMLRequest(testPrerequisites.providerName,
                                           testPrerequisites.requesterId,
                                           testPrerequisites.spTypeRequest);

    RequestHandler requestHandler = new RequestHandler(requestSessionRepository, mockConfigurationService);
    EidasRequest eIDASRequest = requestHandler.handleSAMLPostRequest("RELAY_STATE", samlRequest);
    Assertions.assertNotNull(eIDASRequest.getId());
  }

  @ParameterizedTest
  @MethodSource
  void testInvalidRequest(TestPrerequisites testPrerequisites) throws URISyntaxException
  {
    log.info("TestPrerequisites for this test run: {}", testPrerequisites);
    prepareServiceProviderMock(testPrerequisites.spTypeMetadata);
    prepareConfig();

    String samlRequest = createSAMLRequest(testPrerequisites.providerName,
                                           testPrerequisites.requesterId,
                                           testPrerequisites.spTypeRequest);

    RequestHandler requestHandler = new RequestHandler(requestSessionRepository, mockConfigurationService);
    Assertions.assertThrows(ErrorCodeWithResponseException.class,
                            () -> requestHandler.handleSAMLPostRequest("RELAY_STATE", samlRequest));
  }

  private void prepareConfig()
  {
    EidasMiddlewareConfig config = new EidasMiddlewareConfig();
    EidasMiddlewareConfig.EidConfiguration eidConfiguration = new EidasMiddlewareConfig.EidConfiguration();
    eidConfiguration.getServiceProvider()
                    .add(new ServiceProviderType(PROVIDER_NAME, true, "CVCRefID", "DVCAConf", "ClientKey"));
    eidConfiguration.getServiceProvider()
                    .add(new ServiceProviderType(SERVICE_PROVIDER, true, "CVCRefID", "DVCAConf", "ClientKey"));
    config.setEidConfiguration(eidConfiguration);
    Mockito.when(mockConfigurationService.getConfiguration()).thenReturn(Optional.of(config));
  }

  private void prepareServiceProviderMock(SPTypeEnumeration spTypeMetadata) throws URISyntaxException
  {
    RequestingServiceProvider sp = new RequestingServiceProvider(SERVICE_PROVIDER);

    File keystoreFile = new File(RequestHandlerTest.class.getResource("/de/governikus/eumw/eidasmiddleware/bos-test-tctoken.saml-sign.p12")
                                                         .toURI());
    KeyStore signatureKeystore = KeyStoreSupporter.readKeyStore(keystoreFile, DEFAULT_PASSWORD);
    sp.setSignatureCert((X509Certificate)KeyStoreSupporter.getCertificate(signatureKeystore,
                                                                          "bos-test-tctoken.saml-sign")
                                                          .get());
    sp.setSectorType(spTypeMetadata);
    Mockito.when(mockConfigurationService.getProviderByEntityID("http://localhost:8080/eIDASDemoApplication/Metadata"))
           .thenReturn(sp);
  }

  private String createSAMLRequest(String providerName, String requesterId, SPTypeEnumeration sectorType)
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
      File keystoreFile = new File(RequestHandlerTest.class.getResource("/de/governikus/eumw/eidasmiddleware/bos-test-tctoken.saml-sign.p12")
                                                           .toURI());
      KeyStore keyStore = KeyStoreSupporter.readKeyStore(keystoreFile, DEFAULT_PASSWORD);

      EidasSaml.init();
      EidasSigner signer = new EidasSigner(true,
                                           (PrivateKey)keyStore.getKey("bos-test-tctoken.saml-sign",
                                                                       DEFAULT_PASSWORD.toCharArray()),
                                           (X509Certificate)keyStore.getCertificate("bos-test-tctoken.saml-sign"));

      samlRequest = EidasSaml.createRequest("http://localhost:8080/eIDASDemoApplication/Metadata",
                                            "http://localhost:8080/eIDASDemoApplication/NewReceiverServlet",
                                            providerName,
                                            requesterId,
                                            signer,
                                            reqAtt,
                                            sectorType,
                                            EidasNameIdType.TRANSIENT,
                                            EidasLoaEnum.LOA_HIGH);
    }
    catch (CertificateEncodingException | InitializationException | MarshallingException | SignatureException
      | TransformerFactoryConfigurationError | TransformerException | IOException | UnrecoverableKeyException
      | NoSuchAlgorithmException | KeyStoreException | URISyntaxException e)
    {
      log.error("Can not create Request", e);
      return null;
    }

    return Base64.getEncoder().encodeToString(samlRequest);
  }

  @ToString
  @AllArgsConstructor
  private static class TestPrerequisites
  {

    String providerName;

    String requesterId;

    SPTypeEnumeration spTypeMetadata;

    SPTypeEnumeration spTypeRequest;
  }
}

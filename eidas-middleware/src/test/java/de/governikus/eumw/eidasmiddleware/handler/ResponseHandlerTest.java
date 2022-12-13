package de.governikus.eumw.eidasmiddleware.handler;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import javax.xml.bind.DatatypeConverter;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import de.governikus.eumw.config.EidasMiddlewareConfig;
import de.governikus.eumw.eidascommon.Constants;
import de.governikus.eumw.eidascommon.ErrorCode;
import de.governikus.eumw.eidascommon.ErrorCodeException;
import de.governikus.eumw.eidascommon.Utils;
import de.governikus.eumw.eidasmiddleware.RequestProcessingException;
import de.governikus.eumw.eidasmiddleware.eid.RequestingServiceProvider;
import de.governikus.eumw.eidasmiddleware.entities.RequestSession;
import de.governikus.eumw.eidasmiddleware.repositories.RequestSessionRepository;
import de.governikus.eumw.eidasstarterkit.EidasAttribute;
import de.governikus.eumw.eidasstarterkit.EidasLoaEnum;
import de.governikus.eumw.eidasstarterkit.EidasNaturalPersonAttributes;
import de.governikus.eumw.eidasstarterkit.EidasResponse;
import de.governikus.eumw.eidasstarterkit.TestCaseEnum;
import de.governikus.eumw.eidasstarterkit.person_attributes.natural_persons_attribute.BirthNameAttribute;
import de.governikus.eumw.eidasstarterkit.person_attributes.natural_persons_attribute.CurrentAddressAttribute;
import de.governikus.eumw.eidasstarterkit.person_attributes.natural_persons_attribute.DateOfBirthAttribute;
import de.governikus.eumw.eidasstarterkit.person_attributes.natural_persons_attribute.FamilyNameAttribute;
import de.governikus.eumw.eidasstarterkit.person_attributes.natural_persons_attribute.GivenNameAttribute;
import de.governikus.eumw.eidasstarterkit.person_attributes.natural_persons_attribute.PersonIdentifierAttribute;
import de.governikus.eumw.eidasstarterkit.person_attributes.natural_persons_attribute.PlaceOfBirthAttribute;
import de.governikus.eumw.poseidas.ecardcore.model.ResultMinor;
import de.governikus.eumw.poseidas.eidmodel.data.EIDKeys;
import de.governikus.eumw.poseidas.eidserver.convenience.EIDInfoResultDeselected;
import de.governikus.eumw.poseidas.eidserver.convenience.EIDInfoResultNotOnChip;
import de.governikus.eumw.poseidas.eidserver.convenience.EIDInfoResultPlaceStructured;
import de.governikus.eumw.poseidas.eidserver.convenience.EIDInfoResultString;
import de.governikus.eumw.poseidas.server.eidservice.EIDInternal;
import de.governikus.eumw.poseidas.server.eidservice.EIDResultResponse;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationService;
import de.governikus.eumw.poseidas.server.idprovider.config.CvcTlsCheck;
import de.governikus.eumw.poseidas.server.idprovider.config.KeyPair;
import de.governikus.eumw.poseidas.server.pki.HSMServiceHolder;
import de.governikus.eumw.utils.key.KeyStoreSupporter;
import lombok.extern.slf4j.Slf4j;
import oasis.names.tc.dss._1_0.core.schema.Result;
import se.swedenconnect.opensaml.OpenSAMLInitializer;
import se.swedenconnect.opensaml.OpenSAMLSecurityExtensionConfig;


@Slf4j
@ExtendWith(MockitoExtension.class)
@ExtendWith(SpringExtension.class)
class ResponseHandlerTest
{

  private static final String TEST_P12 = "/eidassignertest.p12";

  private static final String DEFAULT_PASSWORD = "123456";

  public static final String GIVEN_NAME = "GIVEN_NAME";

  public static final String FAMILY_NAME = "FAMILY_NAME";

  public static final String BIRTHNAME = "Birthname";

  private static final String TEST_REF_ID = "LoremImpressi";

  public static final String ENTITY_ID = "entityId";

  private static final String REQUEST_ID = "requestId";

  private static final String EIDAS_SIGNER_TEST_CER = "/EidasSignerTest_x509.cer";

  private static final String RESPONDER = "Responder";

  private final KeyStore signatureKeystore;

  @Mock
  private RequestSessionRepository requestSessionRepository;

  @Mock
  private ConfigurationService mockConfigurationService;

  @Mock
  private HSMServiceHolder mockHsmServiceHolder;

  @Mock
  private EIDInternal mockEidInternal;

  @Mock
  private CvcTlsCheck mockCvcTlsCheck;

  @Mock
  CvcTlsCheck.CvcCheckResults mockCvcResults;

  @Mock
  RequestSession mockRequestSession;

  @Mock
  RequestingServiceProvider mockRequestingServiceProvider;

  private ResponseHandler systemUnderTest;

  public ResponseHandlerTest() throws URISyntaxException
  {
    MockitoAnnotations.initMocks(this);

    File keystoreFile = new File(RequestHandlerTest.class.getResource("/de/governikus/eumw/eidasmiddleware/bos-test-tctoken.saml-sign.p12")
                                                         .toURI());

    signatureKeystore = KeyStoreSupporter.readKeyStore(keystoreFile, DEFAULT_PASSWORD);

  }

  @BeforeAll
  static void prepare() throws Exception
  {
    OpenSAMLInitializer.getInstance().initialize(new OpenSAMLSecurityExtensionConfig());
  }


  @BeforeEach
  void setUp()
  {
    systemUnderTest = spy(new ResponseHandler(requestSessionRepository, mockConfigurationService, mockHsmServiceHolder,
                                              mockEidInternal, mockCvcTlsCheck));
  }

  @Test
  void testGetResultForRefIDNotFound()
  {
    Assertions.assertThrows(RequestProcessingException.class, () -> systemUnderTest.getResultForRefID(TEST_REF_ID));
  }

  @Test
  void testGetResultForRefIDNotFoundSqlException() throws SQLException, ErrorCodeException
  {
    when(requestSessionRepository.findByEidRef("")).thenReturn(Optional.empty());
    Assertions.assertThrows(RequestProcessingException.class, () -> systemUnderTest.getResultForRefID(""));
  }


  @Test
  void testGetResultForRefIDResultMajorOK()
    throws SQLException, ErrorCodeException, IOException, GeneralSecurityException
  {
    // Mock Session Store
    RequestSession mockRequestSession = mock(RequestSession.class);
    when(requestSessionRepository.findByEidRef(anyString())).thenReturn(Optional.of(mockRequestSession));

    // Mock EID Response
    EIDResultResponse mockEidResultResponse = mock(EIDResultResponse.class);
    when(mockEidInternal.getResult(TEST_REF_ID, 0)).thenReturn(mockEidResultResponse);

    // Mock EidInfo
    EIDInfoResultPlaceStructured mockPlaceOfBirthEidInfoResult = mock(EIDInfoResultPlaceStructured.class);
    when(mockEidResultResponse.getEIDInfo(any())).thenReturn(null);
    when(mockEidResultResponse.getEIDInfo(EIDKeys.PLACE_OF_RESIDENCE)).thenReturn(mockPlaceOfBirthEidInfoResult);
    EIDInfoResultNotOnChip mockBirthNameEidInfoResult = mock(EIDInfoResultNotOnChip.class);
    when(mockEidResultResponse.getEIDInfo(EIDKeys.BIRTH_NAME)).thenReturn(mockBirthNameEidInfoResult);


    // Mock EID Reponse Result
    Result mockEidResultResponseResult = mock(Result.class);
    when(mockEidResultResponse.getResult()).thenReturn(mockEidResultResponseResult);
    when(mockEidResultResponseResult.getResultMajor()).thenReturn(Constants.EID_MAJOR_OK);


    // Mock RequestingServiceProvider
    RequestingServiceProvider mockRequestingServiceProvider = mock(RequestingServiceProvider.class);
    when(mockConfigurationService.getProviderByEntityID(mockRequestSession.getReqProviderEntityId())).thenReturn(mockRequestingServiceProvider);
    when(mockRequestingServiceProvider.getEntityID()).thenReturn("asd");
    when(mockRequestingServiceProvider.getAssertionConsumerURL()).thenReturn("asd");
    when(mockRequestingServiceProvider.getEncryptionCert()).thenReturn((X509Certificate)signatureKeystore.getCertificate("bos-test-tctoken.saml-sign"));
    mockConfigurationServiceForEidasSigner();

    // Action
    systemUnderTest.getResultForRefID(TEST_REF_ID);

    // Verify
    verify(systemUnderTest).prepareSAMLResponse(mockRequestingServiceProvider,
                                                mockRequestSession,
                                                mockEidResultResponse);
  }


  @Test
  void testGetResultForRefIDResultMajorErrorByUser()
    throws SQLException, ErrorCodeException, IOException, GeneralSecurityException
  {
    // Mock Session Store
    RequestSession mockRequestSession = mock(RequestSession.class);
    when(requestSessionRepository.findByEidRef(anyString())).thenReturn(Optional.of(mockRequestSession));

    // Mock EID Response
    EIDResultResponse mockEidResultResponse = mock(EIDResultResponse.class);
    when(mockEidInternal.getResult(TEST_REF_ID, 0)).thenReturn(mockEidResultResponse);

    // Mock EID Reponse Result
    Result mockEidResultResponseResult = mock(Result.class);
    when(mockEidResultResponse.getResult()).thenReturn(mockEidResultResponseResult);
    when(mockEidResultResponseResult.getResultMajor()).thenReturn(Constants.EID_MAJOR_ERROR);
    when(mockEidResultResponseResult.getResultMinor()).thenReturn(ResultMinor.SAL_CANCELLATION_BY_USER.toString());

    // Mock RequestingServiceProvider
    RequestingServiceProvider mockRequestingServiceProvider = mock(RequestingServiceProvider.class);
    when(mockConfigurationService.getProviderByEntityID(mockRequestSession.getReqProviderEntityId())).thenReturn(mockRequestingServiceProvider);
    when(mockRequestingServiceProvider.getEntityID()).thenReturn("asd");
    when(mockRequestingServiceProvider.getAssertionConsumerURL()).thenReturn("asd");

    mockConfigurationServiceForEidasSigner();

    // Action
    systemUnderTest.getResultForRefID(TEST_REF_ID);

    // Verify
    verify(systemUnderTest).prepareSAMLErrorResponse(mockRequestingServiceProvider,
                                                     mockRequestSession.getReqId(),
                                                     ErrorCode.CANCELLATION_BY_USER,
                                                     mockEidResultResponse.getResultMessage());
  }

  @Test
  void testGetResultForRefIDResultMajorErrorEidErrorEithResultMessage()
    throws SQLException, ErrorCodeException, IOException, GeneralSecurityException
  {
    // Mock Session Store
    RequestSession mockRequestSession = mock(RequestSession.class);
    when(requestSessionRepository.findByEidRef(anyString())).thenReturn(Optional.of(mockRequestSession));

    // Mock EID Response
    EIDResultResponse mockEidResultResponse = mock(EIDResultResponse.class);
    when(mockEidInternal.getResult(TEST_REF_ID, 0)).thenReturn(mockEidResultResponse);
    when(mockEidResultResponse.getResultMessage()).thenReturn("message");

    // Mock EID Reponse Result
    Result mockEidResultResponseResult = mock(Result.class);
    when(mockEidResultResponse.getResult()).thenReturn(mockEidResultResponseResult);
    when(mockEidResultResponseResult.getResultMajor()).thenReturn(Constants.EID_MAJOR_ERROR);
    when(mockEidResultResponseResult.getResultMinor()).thenReturn(ResultMinor.VR_NO_CONTENT.toString());

    // Mock RequestingServiceProvider
    RequestingServiceProvider mockRequestingServiceProvider = mock(RequestingServiceProvider.class);
    when(mockConfigurationService.getProviderByEntityID(mockRequestSession.getReqProviderEntityId())).thenReturn(mockRequestingServiceProvider);
    when(mockRequestingServiceProvider.getEntityID()).thenReturn("asd");
    when(mockRequestingServiceProvider.getAssertionConsumerURL()).thenReturn("asd");


    mockConfigurationServiceForEidasSigner();

    // Action
    systemUnderTest.getResultForRefID(TEST_REF_ID);

    // Verify
    verify(systemUnderTest).prepareSAMLErrorResponse(mockRequestingServiceProvider,
                                                     mockRequestSession.getReqId(),
                                                     ErrorCode.EID_ERROR,
                                                     "message");
  }

  @Test
  void testGetResultForRefIDResultMajorErrorEidErrorWithoutResultMessage()
    throws SQLException, ErrorCodeException, IOException, GeneralSecurityException
  {
    // Mock Session Store
    RequestSession mockRequestSession = mock(RequestSession.class);
    when(requestSessionRepository.findByEidRef(anyString())).thenReturn(Optional.of(mockRequestSession));

    // Mock EID Response
    EIDResultResponse mockEidResultResponse = mock(EIDResultResponse.class);
    when(mockEidInternal.getResult(TEST_REF_ID, 0)).thenReturn(mockEidResultResponse);
    when(mockEidResultResponse.getResultMessage()).thenReturn("");
    when(mockEidResultResponse.getResultMinor()).thenReturn("ResultMinor");


    // Mock EID Reponse Result
    Result mockEidResultResponseResult = mock(Result.class);
    when(mockEidResultResponse.getResult()).thenReturn(mockEidResultResponseResult);
    when(mockEidResultResponseResult.getResultMajor()).thenReturn("");

    // Mock RequestingServiceProvider
    RequestingServiceProvider mockRequestingServiceProvider = mock(RequestingServiceProvider.class);
    when(mockConfigurationService.getProviderByEntityID(mockRequestSession.getReqProviderEntityId())).thenReturn(mockRequestingServiceProvider);
    when(mockRequestingServiceProvider.getEntityID()).thenReturn("asd");
    when(mockRequestingServiceProvider.getAssertionConsumerURL()).thenReturn("asd");

    mockConfigurationServiceForEidasSigner();

    // Action
    systemUnderTest.getResultForRefID(TEST_REF_ID);

    // Verify
    verify(systemUnderTest).prepareSAMLErrorResponse(mockRequestingServiceProvider,
                                                     mockRequestSession.getReqId(),
                                                     ErrorCode.EID_ERROR,
                                                     "ResultMinor");
  }

  private void mockConfigurationServiceForEidasSigner() throws IOException, GeneralSecurityException
  {
    var eidasMiddlewareConfiguration = new EidasMiddlewareConfig();
    eidasMiddlewareConfiguration.setEidasConfiguration(new EidasMiddlewareConfig.EidasConfiguration());
    eidasMiddlewareConfiguration.getEidasConfiguration().setSignatureKeyPairName("signatureKeystore");
    when(mockConfigurationService.getConfiguration()).thenReturn(Optional.of(eidasMiddlewareConfiguration));
    when(mockConfigurationService.getKeyPair(Mockito.anyString())).thenReturn(new KeyPair(signatureKeystore,
                                                                                          "bos-test-tctoken.saml-sign",
                                                                                          DEFAULT_PASSWORD));
  }

  @Test
  void testGetConsumerURLForRefIDUnkonwnRef() throws SQLException, ErrorCodeException
  {
    when(requestSessionRepository.findByEidRef("")).thenReturn(Optional.empty());
    Assertions.assertThrows(RequestProcessingException.class, () -> systemUnderTest.getConsumerURLForRefID(""));
  }

  @Test
  void testGetConsumerURLForRefID() throws SQLException, ErrorCodeException
  {
    // Mock request session
    RequestSession mockRequestSession = mock(RequestSession.class);
    when(requestSessionRepository.findByEidRef(anyString())).thenReturn(Optional.of(mockRequestSession));

    // Mock ServiceProvider
    RequestingServiceProvider mockRequestingServiceProvider = mock(RequestingServiceProvider.class);
    when(mockConfigurationService.getProviderByEntityID(mockRequestSession.getReqProviderEntityId())).thenReturn(mockRequestingServiceProvider);
    when(mockRequestingServiceProvider.getAssertionConsumerURL()).thenReturn(anyString());

    Assertions.assertDoesNotThrow(() -> systemUnderTest.getConsumerURLForRefID(""));
    Assertions.assertEquals(mockRequestingServiceProvider.getAssertionConsumerURL(),
                            systemUnderTest.getConsumerURLForRefID(""));
  }



  @Test
  void testGetRelayStateForRefIDUnkonwnRef() throws SQLException, ErrorCodeException
  {
    when(requestSessionRepository.findByEidRef("")).thenReturn(Optional.empty());
    Assertions.assertThrows(RequestProcessingException.class, () -> systemUnderTest.getRelayStateForRefID(""));
  }

  @Test
  void testGetRelayStateForRefID() throws SQLException, ErrorCodeException
  {
    // Mock request session
    RequestSession mockRequestSession = mock(RequestSession.class);
    when(requestSessionRepository.findByEidRef(anyString())).thenReturn(Optional.of(mockRequestSession));
    when(mockRequestSession.getRelayState()).thenReturn(anyString());

    Assertions.assertDoesNotThrow(() -> systemUnderTest.getRelayStateForRefID(""));
    Assertions.assertEquals(mockRequestSession.getRelayState(), systemUnderTest.getRelayStateForRefID(""));
  }

  @Test
  void testGetRelayStateForRefIDEmptyOptional() throws SQLException, ErrorCodeException
  {
    // Mock request session
    RequestSession mockRequestSession = mock(RequestSession.class);
    when(requestSessionRepository.findByEidRef(anyString())).thenReturn(Optional.of(mockRequestSession));

    Assertions.assertDoesNotThrow(() -> systemUnderTest.getRelayStateForRefID(""));
    Assertions.assertEquals(null, systemUnderTest.getRelayStateForRefID(""));
  }

  @Test
  void testCreateAllNamesRequestedBirthnameNotFound()
  {
    EIDResultResponse eidResultResponse = mock(EIDResultResponse.class);
    List<EidasAttribute> attributes = spy(new ArrayList<>());
    RequestSession samlReqSession = mock(RequestSession.class);

    // Mock EidResultResponse
    when(eidResultResponse.getEIDInfo(any())).thenReturn(null);
    // BirthName
    EIDInfoResultDeselected birthName = mock(EIDInfoResultDeselected.class);
    when(eidResultResponse.getEIDInfo(EIDKeys.BIRTH_NAME)).thenReturn(birthName);

    // Mock SamlRequestSession
    Map<String, Boolean> requestedAtributes = mock(Map.class);
    when(requestedAtributes.get(EidasNaturalPersonAttributes.BIRTH_NAME.getName())).thenReturn(true);
    when(samlReqSession.getRequestedAttributes()).thenReturn(requestedAtributes);

    Assertions.assertFalse(systemUnderTest.createAllNames(eidResultResponse, attributes, samlReqSession));

  }

  @Test
  void testCreateAllNamesForBirthnameWithBirthname()
  {
    EIDResultResponse eidResultResponse = mock(EIDResultResponse.class);
    List<EidasAttribute> attributes = spy(new ArrayList<>());
    RequestSession samlReqSession = mock(RequestSession.class);

    // Mock EidResultResponse
    when(eidResultResponse.getEIDInfo(any())).thenReturn(null);

    // BirthName
    EIDInfoResultString birthName = mock(EIDInfoResultString.class);
    when(eidResultResponse.getEIDInfo(EIDKeys.BIRTH_NAME)).thenReturn(birthName);
    when(birthName.getResult()).thenReturn(BIRTHNAME);

    // FamilyNames
    EIDInfoResultString familyNames = mock(EIDInfoResultString.class);
    when(familyNames.getResult()).thenReturn(FAMILY_NAME);
    when(eidResultResponse.getEIDInfo(EIDKeys.FAMILY_NAMES)).thenReturn(familyNames);

    // GivenNames
    EIDInfoResultString givenNames = mock(EIDInfoResultString.class);
    when(givenNames.getResult()).thenReturn(GIVEN_NAME);
    when(eidResultResponse.getEIDInfo(EIDKeys.GIVEN_NAMES)).thenReturn(givenNames);


    // Mock SamlRequestSession
    Map<String, Boolean> requestedAttributes = mock(Map.class);
    // Requested Birthname
    when(requestedAttributes.get(EidasNaturalPersonAttributes.BIRTH_NAME.getName())).thenReturn(true);
    when(samlReqSession.getRequestedAttributes()).thenReturn(requestedAttributes);


    systemUnderTest.createAllNames(eidResultResponse, attributes, samlReqSession);
    verify(attributes).add(new BirthNameAttribute(GIVEN_NAME + " " + BIRTHNAME));
  }

  @Test
  void testCreateAllNamesForBirthnameWithoutBirthname()
  {
    EIDResultResponse eidResultResponse = mock(EIDResultResponse.class);
    List<EidasAttribute> attributes = spy(new ArrayList<>());
    RequestSession samlReqSession = mock(RequestSession.class);

    // Mock EidResultResponse
    when(eidResultResponse.getEIDInfo(any())).thenReturn(null);

    // BirthName
    EIDInfoResultString birthName = mock(EIDInfoResultString.class);
    when(eidResultResponse.getEIDInfo(EIDKeys.BIRTH_NAME)).thenReturn(birthName);
    when(birthName.getResult()).thenReturn(""); // No Birthname

    // FamilyNames
    EIDInfoResultString familyNames = mock(EIDInfoResultString.class);
    when(familyNames.getResult()).thenReturn(FAMILY_NAME);
    when(eidResultResponse.getEIDInfo(EIDKeys.FAMILY_NAMES)).thenReturn(familyNames);

    // GivenNames
    EIDInfoResultString givenNames = mock(EIDInfoResultString.class);
    when(givenNames.getResult()).thenReturn(GIVEN_NAME);
    when(eidResultResponse.getEIDInfo(EIDKeys.GIVEN_NAMES)).thenReturn(givenNames);


    // Mock SamlRequestSession
    Map<String, Boolean> requestedAtributes = mock(Map.class);
    // Requested Birthname
    when(requestedAtributes.get(EidasNaturalPersonAttributes.BIRTH_NAME.getName())).thenReturn(true);
    when(samlReqSession.getRequestedAttributes()).thenReturn(requestedAtributes);


    systemUnderTest.createAllNames(eidResultResponse, attributes, samlReqSession);
    verify(attributes).add(new BirthNameAttribute(GIVEN_NAME + " " + FAMILY_NAME));
  }


  @Test
  void testCreateAllNamesForFamilyName()
  {
    EIDResultResponse eidResultResponse = mock(EIDResultResponse.class);
    List<EidasAttribute> attributes = spy(new ArrayList<>());
    RequestSession samlReqSession = mock(RequestSession.class);

    // Mock EidResultResponse
    when(eidResultResponse.getEIDInfo(any())).thenReturn(null);

    // FamilyNames
    EIDInfoResultString familyNames = mock(EIDInfoResultString.class);
    when(familyNames.getResult()).thenReturn(FAMILY_NAME);
    when(eidResultResponse.getEIDInfo(EIDKeys.FAMILY_NAMES)).thenReturn(familyNames);
    // GivenNames
    EIDInfoResultString givenNames = mock(EIDInfoResultString.class);
    when(givenNames.getResult()).thenReturn(GIVEN_NAME);
    when(eidResultResponse.getEIDInfo(EIDKeys.GIVEN_NAMES)).thenReturn(givenNames);

    // Mock SamlRequestSession
    Map<String, Boolean> requestedAtributes = mock(Map.class);
    when(requestedAtributes.get(any())).thenReturn(null);
    // Requested Familyname
    when(requestedAtributes.get(EidasNaturalPersonAttributes.FAMILY_NAME.getName())).thenReturn(true);
    when(samlReqSession.getRequestedAttributes()).thenReturn(requestedAtributes);

    Assertions.assertTrue(systemUnderTest.createAllNames(eidResultResponse, attributes, samlReqSession));
    verify(attributes).add(new FamilyNameAttribute(FAMILY_NAME));
  }

  @Test
  void testCreateAllNamesForFamilyNameNotOnCHip()
  {
    EIDResultResponse eidResultResponse = mock(EIDResultResponse.class);
    List<EidasAttribute> attributes = spy(new ArrayList<>());
    RequestSession samlReqSession = mock(RequestSession.class);

    // Mock EidResultResponse
    when(eidResultResponse.getEIDInfo(any())).thenReturn(null);

    // FamilyNames
    EIDInfoResultNotOnChip familyNames = mock(EIDInfoResultNotOnChip.class);
    when(eidResultResponse.getEIDInfo(EIDKeys.FAMILY_NAMES)).thenReturn(familyNames);
    // GivenNames
    EIDInfoResultString givenNames = mock(EIDInfoResultString.class);
    when(givenNames.getResult()).thenReturn(GIVEN_NAME);
    when(eidResultResponse.getEIDInfo(EIDKeys.GIVEN_NAMES)).thenReturn(givenNames);

    // Mock SamlRequestSession
    Map<String, Boolean> requestedAtributes = mock(Map.class);
    when(requestedAtributes.get(any())).thenReturn(null);
    // Requested Familyname
    when(requestedAtributes.get(EidasNaturalPersonAttributes.FAMILY_NAME.getName())).thenReturn(true);
    when(samlReqSession.getRequestedAttributes()).thenReturn(requestedAtributes);

    Assertions.assertFalse(systemUnderTest.createAllNames(eidResultResponse, attributes, samlReqSession));
    verify(attributes, never()).add(new FamilyNameAttribute(FAMILY_NAME));
  }


  @Test
  void testCreateAllNamesForGivenName()
  {
    EIDResultResponse eidResultResponse = mock(EIDResultResponse.class);
    List<EidasAttribute> attributes = spy(new ArrayList<>());
    RequestSession samlReqSession = mock(RequestSession.class);

    // Mock EidResultResponse
    when(eidResultResponse.getEIDInfo(any())).thenReturn(null);

    // FamilyNames
    EIDInfoResultString familyNames = mock(EIDInfoResultString.class);
    when(familyNames.getResult()).thenReturn(FAMILY_NAME);
    when(eidResultResponse.getEIDInfo(EIDKeys.FAMILY_NAMES)).thenReturn(familyNames);
    // GivenNames
    EIDInfoResultString givenNames = mock(EIDInfoResultString.class);
    when(givenNames.getResult()).thenReturn(GIVEN_NAME);
    when(eidResultResponse.getEIDInfo(EIDKeys.GIVEN_NAMES)).thenReturn(givenNames);

    // Mock SamlRequestSession
    Map<String, Boolean> requestedAtributes = mock(Map.class);
    when(requestedAtributes.get(any())).thenReturn(null);
    // Requested Firstname
    when(requestedAtributes.get(EidasNaturalPersonAttributes.FIRST_NAME.getName())).thenReturn(true);
    when(samlReqSession.getRequestedAttributes()).thenReturn(requestedAtributes);

    Assertions.assertTrue(systemUnderTest.createAllNames(eidResultResponse, attributes, samlReqSession));
    verify(attributes).add(new GivenNameAttribute(GIVEN_NAME));
  }

  @Test
  void testCreateAllNamesForGivenNameNotOnCHip()
  {
    EIDResultResponse eidResultResponse = mock(EIDResultResponse.class);
    List<EidasAttribute> attributes = spy(new ArrayList<>());
    RequestSession samlReqSession = mock(RequestSession.class);

    // Mock EidResultResponse
    when(eidResultResponse.getEIDInfo(any())).thenReturn(null);

    // FamilyNames
    EIDInfoResultString familyNames = mock(EIDInfoResultString.class);
    when(eidResultResponse.getEIDInfo(EIDKeys.FAMILY_NAMES)).thenReturn(familyNames);
    // GivenNames
    EIDInfoResultNotOnChip givenNames = mock(EIDInfoResultNotOnChip.class);
    when(eidResultResponse.getEIDInfo(EIDKeys.GIVEN_NAMES)).thenReturn(givenNames);

    // Mock SamlRequestSession
    Map<String, Boolean> requestedAttributes = mock(Map.class);
    when(requestedAttributes.get(any())).thenReturn(null);
    // Requested Firstname
    when(requestedAttributes.get(EidasNaturalPersonAttributes.FIRST_NAME.getName())).thenReturn(true);
    when(samlReqSession.getRequestedAttributes()).thenReturn(requestedAttributes);

    Assertions.assertFalse(systemUnderTest.createAllNames(eidResultResponse, attributes, samlReqSession));
    verify(attributes, never()).add(new GivenNameAttribute(GIVEN_NAME));
  }


  @Test
  void testCreatePlaceOfResidenceNotRequested()
  {

    EIDResultResponse eidResultResponse = mock(EIDResultResponse.class);
    List<EidasAttribute> attributes = spy(new ArrayList<>());
    RequestSession samlReqSession = mock(RequestSession.class);

    // Mock EidResultResponse
    when(eidResultResponse.getEIDInfo(any())).thenReturn(null);

    // Mock SamlRequestSession
    Map<String, Boolean> requestedAttributes = mock(Map.class);
    when(requestedAttributes.get(EidasNaturalPersonAttributes.CURRENT_ADDRESS.getName())).thenReturn(true);
    when(samlReqSession.getRequestedAttributes()).thenReturn(requestedAttributes);

    Assertions.assertFalse(systemUnderTest.createPlaceOfResidence(eidResultResponse, attributes, samlReqSession));
  }

  @Test
  void testCreatePlaceOfResidence()
  {
    final String street = "Hochschulring 4";
    final String city = "Bremen";
    final String zipCode = "28359";
    final String state = "HB";
    final String country = "D";

    EIDResultResponse eidResultResponse = mock(EIDResultResponse.class);
    List<EidasAttribute> attributes = spy(new ArrayList<>());
    RequestSession samlReqSession = mock(RequestSession.class);

    // Mock EidResultResponse
    EIDInfoResultPlaceStructured place = mock(EIDInfoResultPlaceStructured.class);
    when(place.getStreet()).thenReturn(street);
    when(place.getCity()).thenReturn(city);
    when(place.getZipCode()).thenReturn(zipCode);
    when(place.getState()).thenReturn(state);
    when(place.getCountry()).thenReturn(country);
    when(eidResultResponse.getEIDInfo(EIDKeys.PLACE_OF_RESIDENCE)).thenReturn(place);

    Assertions.assertTrue(systemUnderTest.createPlaceOfResidence(eidResultResponse, attributes, samlReqSession));
    EidasAttribute attr = attributes.get(0);
    Assertions.assertTrue(attr instanceof CurrentAddressAttribute);
    CurrentAddressAttribute addrAttr = (CurrentAddressAttribute)attr;
    Assertions.assertEquals(street, addrAttr.getThoroughfare());
    Assertions.assertEquals(city, addrAttr.getPostName());
    Assertions.assertEquals(zipCode, addrAttr.getPostCode());
    Assertions.assertEquals(state, addrAttr.getAdminunitSecondline());
    Assertions.assertEquals(country, addrAttr.getAdminunitFirstline());
  }

  @Test
  void testPrepareDummyResponseWithoutTestCaseReturnsResponseWithDummyValues() throws Exception
  {
    X509Certificate cert = Utils.readCert(RequestHandlerTest.class.getResourceAsStream(EIDAS_SIGNER_TEST_CER));
    var keyStore = KeyStoreSupporter.readKeyStore(RequestHandlerTest.class.getResourceAsStream(TEST_P12),
                                                  KeyStoreSupporter.KeyStoreType.PKCS12,
                                                  DEFAULT_PASSWORD);
    prepareMocks(keyStore, "eidassignertest", DEFAULT_PASSWORD);
    doReturn(cert).when(mockRequestingServiceProvider).getEncryptionCert();
    var eidasMiddlewareConfig = new EidasMiddlewareConfig();
    eidasMiddlewareConfig.setEidasConfiguration(new EidasMiddlewareConfig.EidasConfiguration());
    eidasMiddlewareConfig.getEidasConfiguration().setCountryCode("DE");
    eidasMiddlewareConfig.getEidasConfiguration().setSignatureKeyPairName("signer");
    eidasMiddlewareConfig.getEidasConfiguration().setPublicServiceProviderName("public");
    when(mockConfigurationService.getConfiguration()).thenReturn(Optional.of(eidasMiddlewareConfig));
    when(mockCvcResults.isCvcPresent()).thenReturn(true);
    when(mockCvcResults.isCvcValidity()).thenReturn(true);
    when(mockCvcResults.isCvcTlsMatch()).thenReturn(true);
    when(mockCvcResults.isCvcUrlMatch()).thenReturn(true);
    ResponseHandler responseHandler = new ResponseHandler(requestSessionRepository, mockConfigurationService,
                                                          mockHsmServiceHolder, mockEidInternal, mockCvcTlsCheck);
    String dummyResponse = responseHandler.prepareDummyResponse(REQUEST_ID, null);

    Assertions.assertNotNull(dummyResponse);

    byte[] samlResponseBytes = DatatypeConverter.parseBase64Binary(dummyResponse);
    Utils.X509KeyPair keypair = Utils.readPKCS12(RequestHandlerTest.class.getResourceAsStream(TEST_P12),
                                                 DEFAULT_PASSWORD.toCharArray());
    Utils.X509KeyPair[] keyPairs = {keypair};
    EidasResponse result = EidasResponse.parse(new ByteArrayInputStream(samlResponseBytes), keyPairs, cert);

    Assertions.assertEquals(EidasLoaEnum.LOA_TEST, result.getLoa());
    Assertions.assertEquals("https://localhost/Metadata", result.getIssuer());
    Assertions.assertEquals(REQUEST_ID, result.getInResponseTo());
    Assertions.assertEquals("consumerUrl", result.getDestination());
    Assertions.assertEquals("DE/DE/123456", result.getNameId().getValue());
    Assertions.assertEquals(ENTITY_ID, result.getRecipient());

    List<EidasAttribute> attributes = result.getAttributes();

    assertAttributes(attributes);
  }

  @Test
  void testRequestWithTestCaseCancellationByUserReturnsErrorResponse() throws Exception
  {
    X509Certificate cert = Utils.readCert(RequestHandlerTest.class.getResourceAsStream(EIDAS_SIGNER_TEST_CER));
    var keyStore = KeyStoreSupporter.readKeyStore(RequestHandlerTest.class.getResourceAsStream(TEST_P12),
                                                  KeyStoreSupporter.KeyStoreType.PKCS12,
                                                  DEFAULT_PASSWORD);
    prepareMocks(keyStore, "eidassignertest", DEFAULT_PASSWORD);
    when(mockCvcResults.isCvcPresent()).thenReturn(true);
    when(mockCvcResults.isCvcValidity()).thenReturn(true);
    when(mockCvcResults.isCvcTlsMatch()).thenReturn(true);
    when(mockCvcResults.isCvcUrlMatch()).thenReturn(true);
    ResponseHandler responseHandler = new ResponseHandler(requestSessionRepository, mockConfigurationService,
                                                          mockHsmServiceHolder, mockEidInternal, mockCvcTlsCheck);
    String dummyResponse = responseHandler.prepareDummyResponse(REQUEST_ID, TestCaseEnum.CANCELLATION_BY_USER);

    Assertions.assertNotNull(dummyResponse);

    byte[] samlResponseBytes = DatatypeConverter.parseBase64Binary(dummyResponse);
    Utils.X509KeyPair keypair = Utils.readPKCS12(RequestHandlerTest.class.getResourceAsStream(TEST_P12),
                                                 DEFAULT_PASSWORD.toCharArray());
    Utils.X509KeyPair[] keyPairs = {keypair};
    EidasResponse result = EidasResponse.parse(new ByteArrayInputStream(samlResponseBytes), keyPairs, cert);

    Assertions.assertTrue(result.getOpenSamlResponse().getStatus().getStatusCode().getValue().contains(RESPONDER));
    Assertions.assertTrue(result.getOpenSamlResponse()
                                .getStatus()
                                .getStatusCode()
                                .getStatusCode()
                                .getValue()
                                .contains("AuthnFailed"));
    Assertions.assertEquals("Authentication cancelled by user",
                            result.getOpenSamlResponse().getStatus().getStatusMessage().getMessage());
    Assertions.assertNull(result.getLoa());
  }

  @Test
  void testRequestWithTestCaseWrongSignatureReturnsErrorResponse() throws Exception
  {
    X509Certificate cert = Utils.readCert(RequestHandlerTest.class.getResourceAsStream(EIDAS_SIGNER_TEST_CER));
    var keyStore = KeyStoreSupporter.readKeyStore(RequestHandlerTest.class.getResourceAsStream(TEST_P12),
                                                  KeyStoreSupporter.KeyStoreType.PKCS12,
                                                  DEFAULT_PASSWORD);
    prepareMocks(keyStore, "eidassignertest", DEFAULT_PASSWORD);
    when(mockCvcResults.isCvcPresent()).thenReturn(true);
    when(mockCvcResults.isCvcValidity()).thenReturn(true);
    when(mockCvcResults.isCvcTlsMatch()).thenReturn(true);
    when(mockCvcResults.isCvcUrlMatch()).thenReturn(true);
    ResponseHandler responseHandler = new ResponseHandler(requestSessionRepository, mockConfigurationService,
                                                          mockHsmServiceHolder, mockEidInternal, mockCvcTlsCheck);
    String dummyResponse = responseHandler.prepareDummyResponse(REQUEST_ID, TestCaseEnum.WRONG_SIGNATURE);

    Assertions.assertNotNull(dummyResponse);

    byte[] samlResponseBytes = DatatypeConverter.parseBase64Binary(dummyResponse);
    Utils.X509KeyPair keypair = Utils.readPKCS12(RequestHandlerTest.class.getResourceAsStream(TEST_P12),
                                                 DEFAULT_PASSWORD.toCharArray());
    Utils.X509KeyPair[] keyPairs = {keypair};
    EidasResponse result = EidasResponse.parse(new ByteArrayInputStream(samlResponseBytes), keyPairs, cert);

    Assertions.assertTrue(result.getOpenSamlResponse().getStatus().getStatusCode().getValue().contains(RESPONDER));
    Assertions.assertEquals("An error was reported from eID-Server: http://www.bsi.bund.de/eid/server/2.0/resultminor/getResult#invalidDocument",
                            result.getOpenSamlResponse().getStatus().getStatusMessage().getMessage());
    Assertions.assertNull(result.getLoa());
  }

  @Test
  void testRequestWithTestCaseUnknownReturnsErrorResponse() throws Exception
  {
    X509Certificate cert = Utils.readCert(RequestHandlerTest.class.getResourceAsStream(EIDAS_SIGNER_TEST_CER));
    var keyStore = KeyStoreSupporter.readKeyStore(RequestHandlerTest.class.getResourceAsStream(TEST_P12),
                                                  KeyStoreSupporter.KeyStoreType.PKCS12,
                                                  DEFAULT_PASSWORD);
    prepareMocks(keyStore, "eidassignertest", DEFAULT_PASSWORD);
    when(mockCvcResults.isCvcPresent()).thenReturn(true);
    when(mockCvcResults.isCvcValidity()).thenReturn(true);
    when(mockCvcResults.isCvcTlsMatch()).thenReturn(true);
    when(mockCvcResults.isCvcUrlMatch()).thenReturn(true);
    ResponseHandler responseHandler = new ResponseHandler(requestSessionRepository, mockConfigurationService,
                                                          mockHsmServiceHolder, mockEidInternal, mockCvcTlsCheck);
    String dummyResponse = responseHandler.prepareDummyResponse(REQUEST_ID, TestCaseEnum.UNKNOWN);

    Assertions.assertNotNull(dummyResponse);

    byte[] samlResponseBytes = DatatypeConverter.parseBase64Binary(dummyResponse);
    Utils.X509KeyPair keypair = Utils.readPKCS12(RequestHandlerTest.class.getResourceAsStream(TEST_P12),
                                                 DEFAULT_PASSWORD.toCharArray());
    Utils.X509KeyPair[] keyPairs = {keypair};
    EidasResponse result = EidasResponse.parse(new ByteArrayInputStream(samlResponseBytes), keyPairs, cert);

    Assertions.assertTrue(result.getOpenSamlResponse().getStatus().getStatusCode().getValue().contains(RESPONDER));
    Assertions.assertEquals("An internal error occurred, see log file of the application server. Details: An unknown error occurred",
                            result.getOpenSamlResponse().getStatus().getStatusMessage().getMessage());
    Assertions.assertNull(result.getLoa());
  }

  @Test
  void testWhenCvcCheckFailedThenReturnErrorResponse() throws Exception
  {
    X509Certificate cert = Utils.readCert(RequestHandlerTest.class.getResourceAsStream(EIDAS_SIGNER_TEST_CER));
    var keyStore = KeyStoreSupporter.readKeyStore(RequestHandlerTest.class.getResourceAsStream(TEST_P12),
                                                  KeyStoreSupporter.KeyStoreType.PKCS12,
                                                  DEFAULT_PASSWORD);
    prepareMocks(keyStore, "eidassignertest", DEFAULT_PASSWORD);
    CvcTlsCheck.CvcCheckResults checkResults = new CvcTlsCheck.CvcCheckResults();
    checkResults.setCvcPresent(true);
    checkResults.setCvcValidity(false);
    checkResults.setCvcUrlMatch(true);
    checkResults.setCvcTlsMatch(true);
    when(mockCvcTlsCheck.checkCvcProvider(anyString())).thenReturn(checkResults);
    ResponseHandler responseHandler = new ResponseHandler(requestSessionRepository, mockConfigurationService,
                                                          mockHsmServiceHolder, mockEidInternal, mockCvcTlsCheck);
    String dummyResponse = responseHandler.prepareDummyResponse(REQUEST_ID, TestCaseEnum.UNKNOWN);

    Assertions.assertNotNull(dummyResponse);

    byte[] samlResponseBytes = DatatypeConverter.parseBase64Binary(dummyResponse);
    Utils.X509KeyPair keypair = Utils.readPKCS12(RequestHandlerTest.class.getResourceAsStream(TEST_P12),
                                                 DEFAULT_PASSWORD.toCharArray());
    Utils.X509KeyPair[] keyPairs = {keypair};
    EidasResponse result = EidasResponse.parse(new ByteArrayInputStream(samlResponseBytes), keyPairs, cert);

    Assertions.assertTrue(result.getOpenSamlResponse().getStatus().getStatusCode().getValue().contains(RESPONDER));
    Assertions.assertEquals("There is an error in the configuration of the server, attribute with the value 'false' need to be fixed. CvcCheckResults{cvcPresent=true, cvcValidity=false, cvcUrlMatch=true, cvcTlsMatch=true}",
                            result.getOpenSamlResponse().getStatus().getStatusMessage().getMessage());
    Assertions.assertNull(result.getLoa());
  }

  private void assertAttributes(List<EidasAttribute> attributes)
  {
    for ( EidasAttribute attribute : attributes )
    {
      if (attribute instanceof GivenNameAttribute)
      {
        Assertions.assertEquals("Erika", attribute.getValue());
        continue;
      }
      if (attribute instanceof FamilyNameAttribute)
      {
        Assertions.assertEquals("Mustermann", attribute.getValue());
        continue;
      }
      if (attribute instanceof BirthNameAttribute)
      {
        Assertions.assertEquals("Erika Gabler", attribute.getValue());
        continue;
      }
      if (attribute instanceof DateOfBirthAttribute)
      {
        Assertions.assertEquals("1964-08-12", attribute.getValue());
        continue;
      }
      if (attribute instanceof PlaceOfBirthAttribute)
      {
        Assertions.assertEquals("Berlin", attribute.getValue());
        continue;
      }
      if (attribute instanceof CurrentAddressAttribute)
      {
        Assertions.assertEquals("Heidestraße 17", ((CurrentAddressAttribute)attribute).getThoroughfare());
        Assertions.assertEquals("Köln", ((CurrentAddressAttribute)attribute).getPostName());
        Assertions.assertEquals("51147", ((CurrentAddressAttribute)attribute).getPostCode());
        Assertions.assertEquals("D", ((CurrentAddressAttribute)attribute).getAdminunitFirstline());
        continue;
      }
      if (attribute instanceof PersonIdentifierAttribute)
      {
        Assertions.assertEquals("DE/DE/123456", attribute.getValue());
        continue;
      }
      Assertions.fail("Invalid attribute in response");
    }
  }

  private void prepareMocks(KeyStore keystore, String alias, String password)
    throws SQLException, ErrorCodeException, IOException, GeneralSecurityException
  {
    when(requestSessionRepository.findById(anyString())).thenReturn(Optional.of(mockRequestSession));
    when(mockRequestSession.getReqProviderEntityId()).thenReturn(ENTITY_ID);
    when(mockConfigurationService.getProviderByEntityID(ENTITY_ID)).thenReturn(mockRequestingServiceProvider);
    when(mockHsmServiceHolder.getKeyStore()).thenReturn(null);
    when(mockConfigurationService.getKeyPair(Mockito.anyString())).thenReturn(new KeyPair(keystore, alias, password));
    when(mockRequestingServiceProvider.getAssertionConsumerURL()).thenReturn("consumerUrl");
    when(mockConfigurationService.getServerURLWithEidasContextPath()).thenReturn("https://localhost");
    when(mockRequestingServiceProvider.getEntityID()).thenReturn(ENTITY_ID);
    when(mockRequestSession.getReqId()).thenReturn(REQUEST_ID);
    var eidasMiddlewareConfig = new EidasMiddlewareConfig();
    eidasMiddlewareConfig.setEidasConfiguration(new EidasMiddlewareConfig.EidasConfiguration());
    eidasMiddlewareConfig.getEidasConfiguration().setPublicServiceProviderName(ENTITY_ID);
    eidasMiddlewareConfig.getEidasConfiguration().setSignatureKeyPairName("signatureKeystore");
    when(mockConfigurationService.getConfiguration()).thenReturn(Optional.of(eidasMiddlewareConfig));
    when(mockCvcTlsCheck.checkCvcProvider(anyString())).thenReturn(mockCvcResults);
  }
}

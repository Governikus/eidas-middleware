package de.governikus.eumw.poseidas.server.monitoring;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.GregorianCalendar;
import java.util.HashSet;
import java.util.Optional;
import java.util.TimeZone;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.snmp4j.CommunityTarget;
import org.snmp4j.PDU;
import org.snmp4j.ScopedPDU;
import org.snmp4j.Snmp;
import org.snmp4j.TransportMapping;
import org.snmp4j.UserTarget;
import org.snmp4j.agent.mo.snmp.DateAndTime;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.mp.MPv3;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.security.AuthHMAC384SHA512;
import org.snmp4j.security.PrivAES256;
import org.snmp4j.security.SecurityLevel;
import org.snmp4j.security.SecurityModels;
import org.snmp4j.security.SecurityProtocols;
import org.snmp4j.security.USM;
import org.snmp4j.security.UsmUser;
import org.snmp4j.smi.Address;
import org.snmp4j.smi.GenericAddress;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.VariableBinding;
import org.snmp4j.transport.DefaultUdpTransportMapping;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import de.governikus.eumw.config.EidasMiddlewareConfig;
import de.governikus.eumw.config.ServiceProviderType;
import de.governikus.eumw.poseidas.config.OverviewController;
import de.governikus.eumw.poseidas.eidserver.crl.CertificationRevocationListImpl;
import de.governikus.eumw.poseidas.eidserver.model.signeddata.MasterList;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationService;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationTestHelper;
import de.governikus.eumw.poseidas.server.pki.TerminalPermission;
import de.governikus.eumw.poseidas.server.pki.TerminalPermissionAO;
import de.governikus.eumw.poseidas.service.MetadataService;
import org.springframework.test.util.TestSocketUtils;

@ActiveProfiles("db") // Use application-db.properties
@SpringBootTest
class SNMPAgentTest
{

  private static final String DVCA_CONF = "dvcaConf";

  private static final String CLIENT_KEY = "clientKey";

  // These mocked beans are necessary to start the application context
  @MockBean
  private MetadataService metadataService;

  @MockBean
  private OverviewController overviewController;

  @MockBean
  private ConfigurationService configurationService;

  @Autowired
  private TerminalPermissionAO facade;

  private Snmp snmp;

  private UserTarget userTarget;

  static int snmpPort;

  @DynamicPropertySource
  static void snmpProperties(DynamicPropertyRegistry dynamicPropertyRegistry)
  {
    snmpPort = TestSocketUtils.findAvailableTcpPort();
    dynamicPropertyRegistry.add("poseidas.snmp.agentport", () -> snmpPort);
  }

  @BeforeAll
  static void init()
  {
    TimeZone.setDefault(TimeZone.getTimeZone("GMT"));
  }

  @BeforeEach
  void setUp() throws Exception
  {
    Address targetAddress = GenericAddress.parse("udp:127.0.0.1/" + snmpPort);
    TransportMapping transport = new DefaultUdpTransportMapping();
    snmp = new Snmp(transport);
    USM usm = new USM(SecurityProtocols.getInstance(), new OctetString(MPv3.createLocalEngineID()), 0);
    SecurityModels.getInstance().addSecurityModel(usm);
    transport.listen();
    snmp.getUSM()
        .addUser(new UsmUser(new OctetString("test"), AuthHMAC384SHA512.ID, new OctetString("authpwdtest"),
                             PrivAES256.ID, new OctetString("privpwdtest")));
    userTarget = new UserTarget();
    userTarget.setAddress(targetAddress);
    userTarget.setRetries(2);
    userTarget.setTimeout(1500);
    userTarget.setSecurityLevel(SecurityLevel.AUTH_PRIV);
    userTarget.setSecurityName(new OctetString("test"));
    userTarget.setVersion(SnmpConstants.version3);
    Mockito.when(configurationService.getConfiguration()).thenReturn(Optional.of(prepareConfiguration()));
  }

  @Test
  void testSnmpAgentWhenOIDGetProviderNameThenReturnProviderName() throws Exception
  {
    PDU pdu = new ScopedPDU();
    pdu.add(new VariableBinding(new OID(SNMPConstants.GetOID.PROVIDER_NAME_GET.getValue() + ".0")));
    pdu.setType(PDU.GET);

    ResponseEvent responseEvent = snmp.send(pdu, userTarget);

    Assertions.assertEquals("DefaultProvider", responseEvent.getResponse().get(0).getVariable().toString());
  }

  @Test
  void testWhenOIDGetProviderNameSPIndexNotExistThenReturnErrorStatusResourceUnavailable() throws Exception
  {
    PDU pdu = new ScopedPDU();
    pdu.add(new VariableBinding(new OID(SNMPConstants.GetOID.PROVIDER_NAME_GET.getValue() + ".42")));
    pdu.setType(PDU.GET);

    ResponseEvent responseEvent = snmp.send(pdu, userTarget);

    Assertions.assertEquals(SnmpConstants.SNMP_ERROR_RESOURCE_UNAVAILABLE,
                            responseEvent.getResponse().getErrorStatus());
    Assertions.assertEquals("Null", responseEvent.getResponse().get(0).getVariable().toString());
  }

  @Test
  void testWhenBlacklistAvailableThenReturnStatusSuccess() throws Exception
  {
    PDU pdu = new ScopedPDU();
    pdu.add(new VariableBinding(new OID(SNMPConstants.GetOID.BLACKLIST_GET_LIST_AVAILABLE.getValue() + ".1")));
    pdu.setType(PDU.GET);

    ResponseEvent responseEvent = snmp.send(pdu, userTarget);

    Assertions.assertEquals("1", responseEvent.getResponse().get(0).getVariable().toString());
  }

  @Test
  void testWhenBlacklistNotAvailableThenReturnErrorStatusResourceUnavailable() throws Exception
  {
    PDU pdu = new ScopedPDU();
    pdu.add(new VariableBinding(new OID(SNMPConstants.GetOID.BLACKLIST_GET_LIST_AVAILABLE.getValue() + ".5")));
    pdu.setType(PDU.GET);

    ResponseEvent responseEvent = snmp.send(pdu, userTarget);

    Assertions.assertEquals(SnmpConstants.SNMP_ERROR_RESOURCE_UNAVAILABLE,
                            responseEvent.getResponse().getErrorStatus());
    Assertions.assertEquals("Null", responseEvent.getResponse().get(0).getVariable().toString());
  }

  @Test
  void testWhenBlacklistLastSuccessfulRetrievalThenReturnDate() throws Exception
  {
    LocalDateTime expectedLocalDateTime = LocalDateTime.parse("2021-01-26T12:43:23.900");
    PDU pdu = new ScopedPDU();
    pdu.add(new VariableBinding(new OID(SNMPConstants.GetOID.BLACKLIST_GET_LAST_SUCCESSFUL_RETRIEVAL.getValue()
                                        + ".1")));
    pdu.setType(PDU.GET);

    ResponseEvent responseEvent = snmp.send(pdu, userTarget);

    LocalDateTime actualLocalDateTime = getLocalDateTimeFromResponse(responseEvent);
    Assertions.assertEquals(expectedLocalDateTime, actualLocalDateTime);
  }

  @Test
  void testWhenBlackListLastSuccessfulRetrievalNotAvailableThenReturnErrorStatusResourceUnavailable() throws Exception
  {
    PDU pdu = new ScopedPDU();
    pdu.add(new VariableBinding(new OID(SNMPConstants.GetOID.BLACKLIST_GET_LAST_SUCCESSFUL_RETRIEVAL.getValue()
                                        + ".5")));
    pdu.setType(PDU.GET);

    ResponseEvent responseEvent = snmp.send(pdu, userTarget);

    Assertions.assertEquals(SnmpConstants.SNMP_ERROR_RESOURCE_UNAVAILABLE,
                            responseEvent.getResponse().getErrorStatus());
    Assertions.assertEquals("Null", responseEvent.getResponse().get(0).getVariable().toString());
  }

  @Test
  void testWhenMasterListAvailableThenReturnStatusSuccess() throws Exception
  {
    PDU pdu = new ScopedPDU();
    pdu.add(new VariableBinding(new OID(SNMPConstants.GetOID.MASTERLIST_GET_LIST_AVAILABLE.getValue() + ".1")));
    pdu.setType(PDU.GET);

    ResponseEvent responseEvent = snmp.send(pdu, userTarget);

    Assertions.assertEquals("1", responseEvent.getResponse().get(0).getVariable().toString());
  }

  @Test
  void testWhenMasterListNotAvailableThenReturnErrorStatusResourceUnavailable() throws Exception
  {
    PDU pdu = new ScopedPDU();
    pdu.add(new VariableBinding(new OID(SNMPConstants.GetOID.MASTERLIST_GET_LIST_AVAILABLE.getValue() + ".5")));
    pdu.setType(PDU.GET);

    ResponseEvent responseEvent = snmp.send(pdu, userTarget);

    Assertions.assertEquals(SnmpConstants.SNMP_ERROR_RESOURCE_UNAVAILABLE,
                            responseEvent.getResponse().getErrorStatus());
    Assertions.assertEquals("Null", responseEvent.getResponse().get(0).getVariable().toString());
  }

  @Test
  void testWhenMasterListLastSuccessfulRetrievalThenReturnDate() throws Exception
  {
    LocalDateTime expectedLocalDateTime = LocalDateTime.parse("2021-01-26T12:43:25.300");
    PDU pdu = new ScopedPDU();
    pdu.add(new VariableBinding(new OID(SNMPConstants.GetOID.MASTERLIST_GET_LAST_SUCCESSFUL_RETRIEVAL.getValue()
                                        + ".1")));
    pdu.setType(PDU.GET);

    ResponseEvent responseEvent = snmp.send(pdu, userTarget);

    LocalDateTime actualLocalDateTime = getLocalDateTimeFromResponse(responseEvent);
    Assertions.assertEquals(expectedLocalDateTime, actualLocalDateTime);
  }

  @Test
  void testWhenMasterListLastSuccessfulRetrievalNotAvailableThenReturnErrorStatusResourceUnavailable() throws Exception
  {
    PDU pdu = new ScopedPDU();
    pdu.add(new VariableBinding(new OID(SNMPConstants.GetOID.MASTERLIST_GET_LAST_SUCCESSFUL_RETRIEVAL.getValue()
                                        + ".5")));
    pdu.setType(PDU.GET);

    ResponseEvent responseEvent = snmp.send(pdu, userTarget);

    Assertions.assertEquals(SnmpConstants.SNMP_ERROR_RESOURCE_UNAVAILABLE,
                            responseEvent.getResponse().getErrorStatus());
    Assertions.assertEquals("Null", responseEvent.getResponse().get(0).getVariable().toString());
  }

  @Test
  void testWhenDefectListAvailableThenReturnStatusSuccess() throws Exception
  {
    PDU pdu = new ScopedPDU();
    pdu.add(new VariableBinding(new OID(SNMPConstants.GetOID.DEFECTLIST_GET_LIST_AVAILABLE.getValue() + ".1")));
    pdu.setType(PDU.GET);

    ResponseEvent responseEvent = snmp.send(pdu, userTarget);

    Assertions.assertEquals("1", responseEvent.getResponse().get(0).getVariable().toString());
  }

  @Test
  void testWhenDefectListNotAvailableThenReturnErrorStatusResourceUnavailable() throws Exception
  {
    PDU pdu = new ScopedPDU();
    pdu.add(new VariableBinding(new OID(SNMPConstants.GetOID.DEFECTLIST_GET_LIST_AVAILABLE.getValue() + ".5")));
    pdu.setType(PDU.GET);

    ResponseEvent responseEvent = snmp.send(pdu, userTarget);

    Assertions.assertEquals(SnmpConstants.SNMP_ERROR_RESOURCE_UNAVAILABLE,
                            responseEvent.getResponse().getErrorStatus());
    Assertions.assertEquals("Null", responseEvent.getResponse().get(0).getVariable().toString());
  }

  @Test
  void testWhenDefectListLastSuccessfulRetrievalThenReturnDate() throws Exception
  {
    LocalDateTime expectedLocalDateTime = LocalDateTime.parse("2021-01-26T12:43:25.300");
    PDU pdu = new ScopedPDU();
    pdu.add(new VariableBinding(new OID(SNMPConstants.GetOID.DEFECTLIST_GET_LAST_SUCCESSFUL_RETRIEVAL.getValue()
                                        + ".1")));
    pdu.setType(PDU.GET);

    ResponseEvent responseEvent = snmp.send(pdu, userTarget);

    LocalDateTime actualLocalDateTime = getLocalDateTimeFromResponse(responseEvent);
    Assertions.assertEquals(expectedLocalDateTime, actualLocalDateTime);
  }

  @Test
  void testWhenDefectListLastSuccessfulRetrievalNotAvailableThenReturnErrorStatusResourceUnavailable() throws Exception
  {
    PDU pdu = new ScopedPDU();
    pdu.add(new VariableBinding(new OID(SNMPConstants.GetOID.DEFECTLIST_GET_LAST_SUCCESSFUL_RETRIEVAL.getValue()
                                        + ".5")));
    pdu.setType(PDU.GET);

    ResponseEvent responseEvent = snmp.send(pdu, userTarget);

    Assertions.assertEquals(SnmpConstants.SNMP_ERROR_RESOURCE_UNAVAILABLE,
                            responseEvent.getResponse().getErrorStatus());
    Assertions.assertEquals("Null", responseEvent.getResponse().get(0).getVariable().toString());
  }

  @Test
  void testWhenPendingRSCAvailableThenReturnStatusSuccess() throws Exception
  {
    PDU pdu = new ScopedPDU();
    pdu.add(new VariableBinding(new OID(SNMPConstants.GetOID.RSC_GET_PENDING_AVAILABLE.getValue() + ".2")));
    pdu.setType(PDU.GET);
    ResponseEvent responseEvent = snmp.send(pdu, userTarget);
    Assertions.assertEquals("1", responseEvent.getResponse().get(0).getVariable().toString());
  }

  @Test
  void testWhenPendingRSCNotAvailableThenReturnStatusUnavailable() throws Exception
  {
    PDU pdu = new ScopedPDU();
    pdu.add(new VariableBinding(new OID(SNMPConstants.GetOID.RSC_GET_PENDING_AVAILABLE.getValue() + ".1")));
    pdu.setType(PDU.GET);

    ResponseEvent responseEvent = snmp.send(pdu, userTarget);

    Assertions.assertEquals("0", responseEvent.getResponse().get(0).getVariable().toString());
  }

  @Test
  void testWhenRSCAvailableThenReturnValidUntilDate() throws Exception
  {
    LocalDateTime expectedLocalDateTime = LocalDateTime.parse("2024-02-05T09:25:25");
    PDU pdu = new ScopedPDU();
    pdu.add(new VariableBinding(new OID(SNMPConstants.GetOID.RSC_GET_CURRENT_CERTIFICATE_VALID_UNTIL.getValue()
                                        + ".1")));
    pdu.setType(PDU.GET);

    ResponseEvent responseEvent = snmp.send(pdu, userTarget);

    LocalDateTime actualLocalDateTime = getLocalDateTimeFromResponse(responseEvent);
    Assertions.assertEquals(expectedLocalDateTime, actualLocalDateTime);
  }

  @Test
  void testWhenCurrentRSCNotAvailableThenReturnErrorStatusResourceUnavailable() throws Exception
  {
    PDU pdu = new ScopedPDU();
    pdu.add(new VariableBinding(new OID(SNMPConstants.GetOID.RSC_GET_CURRENT_CERTIFICATE_VALID_UNTIL.getValue()
                                        + ".2")));
    pdu.setType(PDU.GET);

    ResponseEvent responseEvent = snmp.send(pdu, userTarget);

    Assertions.assertEquals(SnmpConstants.SNMP_ERROR_RESOURCE_UNAVAILABLE,
                            responseEvent.getResponse().getErrorStatus());
    Assertions.assertEquals("Null", responseEvent.getResponse().get(0).getVariable().toString());
  }

  @Test
  void testWhenCRLNotInitializedThenReturnStatusNotPresent() throws Exception
  {
    CertificationRevocationListImpl.reset();
    PDU pdu = new ScopedPDU();
    pdu.add(new VariableBinding(new OID(SNMPConstants.GetOID.CRL_GET_AVAILABLE.getValue())));
    pdu.setType(PDU.GET);

    ResponseEvent responseEvent = snmp.send(pdu, userTarget);

    Assertions.assertEquals("0", responseEvent.getResponse().get(0).getVariable().toString());
  }

  @Test
  void testWhenCRLInitializedThenReturnStatusPresent() throws Exception
  {
    CertificationRevocationListImpl.reset();
    TerminalPermission terminalPermission = facade.getTerminalPermission("A");
    MasterList ml = new MasterList(terminalPermission.getMasterList());
    CertificationRevocationListImpl.initialize(new HashSet<>(ml.getCertificates()), configurationService);
    PDU pdu = new ScopedPDU();
    pdu.add(new VariableBinding(new OID(SNMPConstants.GetOID.CRL_GET_AVAILABLE.getValue())));
    pdu.setType(PDU.GET);

    ResponseEvent responseEvent = snmp.send(pdu, userTarget);

    Assertions.assertEquals("1", responseEvent.getResponse().get(0).getVariable().toString());
    CertificationRevocationListImpl.reset();
  }

  @Test
  void testWhenCRLLastSuccessfulRetrievalNotSuccessfulThenReturnErrorStatusResourceUnavailable() throws Exception
  {
    TerminalPermission terminalPermission = facade.getTerminalPermission("A");
    MasterList ml = new MasterList(terminalPermission.getMasterList());
    CertificationRevocationListImpl.initialize(new HashSet<>(ml.getCertificates()), configurationService);
    PDU pdu = new ScopedPDU();
    pdu.add(new VariableBinding(new OID(SNMPConstants.GetOID.CRL_GET_LAST_SUCCESSFUL_RETRIEVAL.getValue())));
    pdu.setType(PDU.GET);

    ResponseEvent responseEvent = snmp.send(pdu, userTarget);

    Assertions.assertEquals(SnmpConstants.SNMP_ERROR_RESOURCE_UNAVAILABLE,
                            responseEvent.getResponse().getErrorStatus());
    Assertions.assertEquals("Null", responseEvent.getResponse().get(0).getVariable().toString());
  }

  @Test
  void testWhenCVCPresentThenReturnStatusCodePresent() throws Exception
  {
    PDU pdu = new ScopedPDU();
    pdu.add(new VariableBinding(new OID(SNMPConstants.GetOID.CVC_GET_PRESENT.getValue() + ".1")));
    pdu.setType(PDU.GET);

    ResponseEvent responseEvent = snmp.send(pdu, userTarget);

    Assertions.assertEquals("1", responseEvent.getResponse().get(0).getVariable().toString());
  }

  @Test
  void testWhenCVCNotPresentThenReturnStatusCodeNotPresent() throws Exception
  {
    PDU pdu = new ScopedPDU();
    pdu.add(new VariableBinding(new OID(SNMPConstants.GetOID.CVC_GET_PRESENT.getValue() + ".9")));
    pdu.setType(PDU.GET);

    ResponseEvent responseEvent = snmp.send(pdu, userTarget);

    Assertions.assertEquals("0", responseEvent.getResponse().get(0).getVariable().toString());
  }

  @Test
  void testWhenCVCSubjectUrlPresentReturnSubjectUrl() throws Exception
  {
    PDU pdu = new ScopedPDU();
    pdu.add(new VariableBinding(new OID(SNMPConstants.GetOID.CVC_GET_SUBJECT_URL.getValue() + ".1")));
    pdu.setType(PDU.GET);

    ResponseEvent responseEvent = snmp.send(pdu, userTarget);

    Assertions.assertEquals("https://some.test.url.de", responseEvent.getResponse().get(0).getVariable().toString());
  }

  @Test
  void testWhenCVCSubjectUrlNotPresentThenReturnErrorStatusResourceUnavailable() throws Exception
  {
    PDU pdu = new ScopedPDU();
    pdu.add(new VariableBinding(new OID(SNMPConstants.GetOID.CVC_GET_SUBJECT_URL.getValue() + ".9")));
    pdu.setType(PDU.GET);

    ResponseEvent responseEvent = snmp.send(pdu, userTarget);

    Assertions.assertEquals(SnmpConstants.SNMP_ERROR_RESOURCE_UNAVAILABLE,
                            responseEvent.getResponse().getErrorStatus());
    Assertions.assertEquals("Null", responseEvent.getResponse().get(0).getVariable().toString());
  }

  @Test
  void testWhenCVCPresentThenReturnValidUntilDate() throws Exception
  {
    LocalDateTime expectedLocalDateTime = LocalDateTime.parse("2034-03-17T00:00:00.000");
    PDU pdu = new ScopedPDU();
    pdu.add(new VariableBinding(new OID(SNMPConstants.GetOID.CVC_GET_VALID_UNTIL.getValue() + ".1")));
    pdu.setType(PDU.GET);

    ResponseEvent responseEvent = snmp.send(pdu, userTarget);

    LocalDateTime actualLocalDateTime = getLocalDateTimeFromResponse(responseEvent);
    Assertions.assertEquals(expectedLocalDateTime, actualLocalDateTime);
  }

  @Test
  void testWhenCVCNotPresentThenReturnErrorStatusResourceUnavailable() throws Exception
  {
    PDU pdu = new ScopedPDU();
    pdu.add(new VariableBinding(new OID(SNMPConstants.GetOID.CVC_GET_VALID_UNTIL.getValue() + ".9")));
    pdu.setType(PDU.GET);

    ResponseEvent responseEvent = snmp.send(pdu, userTarget);

    Assertions.assertEquals(SnmpConstants.SNMP_ERROR_RESOURCE_UNAVAILABLE,
                            responseEvent.getResponse().getErrorStatus());
    Assertions.assertEquals("Null", responseEvent.getResponse().get(0).getVariable().toString());
  }

  @Test
  void testWhenOIDInvalidThenReturnStatusResourceUnavailable() throws Exception
  {
    PDU pdu = new ScopedPDU();
    pdu.add(new VariableBinding(new OID("1.3.6.1.4.1.28939.3.1.2.1.99.1")));
    pdu.setType(PDU.GET);

    ResponseEvent responseEvent = snmp.send(pdu, userTarget);

    Assertions.assertEquals(SnmpConstants.SNMP_ERROR_RESOURCE_UNAVAILABLE,
                            responseEvent.getResponse().getErrorStatus());
    Assertions.assertEquals("Null", responseEvent.getResponse().get(0).getVariable().toString());

    pdu = new ScopedPDU();
    pdu.add(new VariableBinding(new OID("1.3.6.1.4.1.28939.3.1.1.42.1")));
    pdu.setType(PDU.GET);

    responseEvent = snmp.send(pdu, userTarget);

    Assertions.assertEquals(SnmpConstants.SNMP_ERROR_RESOURCE_UNAVAILABLE,
                            responseEvent.getResponse().getErrorStatus());
    Assertions.assertEquals("Null", responseEvent.getResponse().get(0).getVariable().toString());
  }

  @Test
  void testWhenPDUTypeBulkThenReturnStatusGeneralError() throws Exception
  {
    PDU pdu = new ScopedPDU();
    pdu.add(new VariableBinding(new OID("1.3.6.1.4.1.28939.3.1.2.1.99.1")));
    pdu.setType(PDU.GETBULK);

    ResponseEvent responseEvent = snmp.send(pdu, userTarget);

    Assertions.assertEquals(SnmpConstants.SNMP_ERROR_GENERAL_ERROR, responseEvent.getResponse().getErrorStatus());
  }

  @Test
  void testWhenSnmpVersionLessThreeThenResponseNull() throws Exception
  {
    Address targetAddress = GenericAddress.parse("udp:127.0.0.1/10161");
    CommunityTarget target = new CommunityTarget();
    target.setCommunity(new OctetString("public"));
    target.setAddress(targetAddress);
    target.setRetries(2);
    target.setTimeout(1500);
    target.setVersion(SnmpConstants.version1);
    PDU pdu = new PDU();
    pdu.add(new VariableBinding(new OID(SNMPConstants.GetOID.PROVIDER_NAME_GET.getValue() + ".0")));
    pdu.setType(PDU.GET);

    ResponseEvent responseEvent = snmp.send(pdu, target);

    Assertions.assertNull(responseEvent.getResponse());
  }

  @Test
  void testWhenPDUTypeGetNextThenReturnNextOID() throws Exception
  {
    // Test OID is before first global eumw OID
    PDU pdu = new ScopedPDU();
    pdu.add(new VariableBinding(new OID("1.3")));
    pdu.setType(PDU.GETNEXT);

    ResponseEvent responseEvent = snmp.send(pdu, userTarget);

    Assertions.assertEquals(new OID(SNMPConstants.GetOID.CRL_GET_AVAILABLE.getValue()),
                            responseEvent.getResponse().get(0).getOid());
    Assertions.assertEquals("1", responseEvent.getResponse().get(0).getVariable().toString());

    // Test OID ServiceProviderSpecific
    pdu = new ScopedPDU();
    pdu.add(new VariableBinding(new OID(SNMPConstants.GetOID.PROVIDER_NAME_GET.getValue() + ".0")));
    pdu.setType(PDU.GETNEXT);

    responseEvent = snmp.send(pdu, userTarget);

    Assertions.assertEquals(new OID(SNMPConstants.GetOID.PROVIDER_NAME_GET.getValue() + ".1"),
                            responseEvent.getResponse().get(0).getOid());
    Assertions.assertEquals("TestbedA", responseEvent.getResponse().get(0).getVariable().toString());

    // Test OID ServiceProviderTable
    pdu = new ScopedPDU();
    pdu.add(new VariableBinding(new OID(SNMPConstants.GetOID.PROVIDER_NAME_GET.getValue())));
    pdu.setType(PDU.GETNEXT);

    responseEvent = snmp.send(pdu, userTarget);

    Assertions.assertEquals(new OID(SNMPConstants.GetOID.PROVIDER_NAME_GET.getValue() + ".0"),
                            responseEvent.getResponse().get(0).getOid());
    Assertions.assertEquals("DefaultProvider", responseEvent.getResponse().get(0).getVariable().toString());

    // Test OID ServiceProvider last index of an service provider entry
    pdu = new ScopedPDU();
    pdu.add(new VariableBinding(new OID(SNMPConstants.GetOID.PROVIDER_NAME_GET.getValue() + ".9")));
    pdu.setType(PDU.GETNEXT);

    responseEvent = snmp.send(pdu, userTarget);
    Assertions.assertEquals(new OID(SNMPConstants.GetOID.CVC_GET_PRESENT.getValue() + ".0"),
                            responseEvent.getResponse().get(0).getOid());
    Assertions.assertEquals("1", responseEvent.getResponse().get(0).getVariable().toString());

    // Test OID out of available eumw oids
    pdu = new ScopedPDU();
    pdu.add(new VariableBinding(new OID("1.3.6.1.4.1.28940.42")));
    pdu.setType(PDU.GETNEXT);

    responseEvent = snmp.send(pdu, userTarget);

    Assertions.assertEquals(SnmpConstants.SNMP_ERROR_NO_SUCH_NAME, responseEvent.getResponse().getErrorStatus());
    Assertions.assertEquals("Null", responseEvent.getResponse().get(0).getVariable().toString());
  }

  private LocalDateTime getLocalDateTimeFromResponse(ResponseEvent responseEvent)
  {
    GregorianCalendar actualDate = DateAndTime.makeCalendar(OctetString.fromHexString(responseEvent.getResponse()
                                                                                                   .get(0)
                                                                                                   .getVariable()
                                                                                                   .toString(),
                                                                                      ':'));
    TimeZone timeZone = actualDate.getTimeZone();
    ZoneId zoneId1 = timeZone.toZoneId();
    return LocalDateTime.ofInstant(actualDate.toInstant(), zoneId1);
  }

  private EidasMiddlewareConfig prepareConfiguration() throws Exception
  {
    EidasMiddlewareConfig configuration = ConfigurationTestHelper.createValidConfiguration();
    ServiceProviderType sp = configuration.getEidConfiguration().getServiceProvider().get(0);
    sp.setName("DefaultProvider");
    sp.setCVCRefID("F");
    configuration.getEidConfiguration()
                 .getServiceProvider()
                 .add(new ServiceProviderType("TestbedA", true, "A", DVCA_CONF, CLIENT_KEY));
    configuration.getEidConfiguration()
                 .getServiceProvider()
                 .add(new ServiceProviderType("TestbedB", true, "B", DVCA_CONF, CLIENT_KEY));
    configuration.getEidConfiguration()
                 .getServiceProvider()
                 .add(new ServiceProviderType("TestbedC", true, "C", DVCA_CONF, CLIENT_KEY));
    configuration.getEidConfiguration()
                 .getServiceProvider()
                 .add(new ServiceProviderType("TestbedD", true, "D", DVCA_CONF, CLIENT_KEY));
    configuration.getEidConfiguration()
                 .getServiceProvider()
                 .add(new ServiceProviderType("TestbedERSA", true, "ERSA", DVCA_CONF, CLIENT_KEY));
    configuration.getEidConfiguration()
                 .getServiceProvider()
                 .add(new ServiceProviderType("TestbedEDSA", true, "EDSA", DVCA_CONF, CLIENT_KEY));
    configuration.getEidConfiguration()
                 .getServiceProvider()
                 .add(new ServiceProviderType("TestbedECDSA", true, "ECDSA", DVCA_CONF, CLIENT_KEY));
    configuration.getEidConfiguration()
                 .getServiceProvider()
                 .add(new ServiceProviderType("TestbedF", true, "F", DVCA_CONF, CLIENT_KEY));
    configuration.getEidConfiguration()
                 .getServiceProvider()
                 .add(new ServiceProviderType("TestbedG", true, "G", DVCA_CONF, CLIENT_KEY));
    return configuration;
  }
}

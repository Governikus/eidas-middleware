package de.governikus.eumw.poseidas.config;


import static org.mockito.Mockito.when;

import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.apache.commons.lang3.ArrayUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.w3c.dom.NodeList;

import com.gargoylesoftware.htmlunit.html.DomElement;
import com.gargoylesoftware.htmlunit.html.DomNodeList;
import com.gargoylesoftware.htmlunit.html.HtmlDivision;
import com.gargoylesoftware.htmlunit.html.HtmlElement;
import com.gargoylesoftware.htmlunit.html.HtmlPage;

import de.governikus.eumw.config.EidasMiddlewareConfig;
import de.governikus.eumw.config.ServiceProviderType;
import de.governikus.eumw.eidascommon.ContextPaths;
import de.governikus.eumw.poseidas.config.base.TestConfiguration;
import de.governikus.eumw.poseidas.config.base.WebAdminTestBase;
import de.governikus.eumw.poseidas.eidmodel.TerminalData;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationService;
import de.governikus.eumw.poseidas.server.idprovider.config.CvcTlsCheck;
import de.governikus.eumw.poseidas.server.pki.PermissionDataHandling;
import de.governikus.eumw.poseidas.server.pki.RequestSignerCertificateService;
import de.governikus.eumw.poseidas.server.pki.TerminalPermissionAOBean;
import de.governikus.eumw.poseidas.server.pki.TlsClientRenewalService;
import de.governikus.eumw.poseidas.server.pki.entities.TerminalPermission;
import de.governikus.eumw.utils.key.SecurityProvider;


@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {"server.servlet.context-path=/"})
@Import(TestConfiguration.class)
@DisplayName("Test Status page")
class DashboardControllerTest extends WebAdminTestBase
{

  private final static String CVC_DESCRIPTION = "MIGQBgoEAH8ABwMBAwEBoRYMFEdvdmVybmlrdXMgVGVzdCBEVkNBohoTGGh0dHA6Ly93d3cuZ292ZXJuaWt1cy5kZaMKDAhCUFIgODQ0OKQYExZodHRwczovL2xvY2FsaG9zdDo4NDQ4pQIMAKckMSIEIF2fEYwONIdvuJzSQKQU1n+8ch2iQHhs5f0cLrQsx8ok";

  private static final String OK = "✔";

  private static final String NOT_OK = "❌";

  private static final String NOT_PRESENT = "-";

  public static final String SP1_REF_ID = "firstProvider";

  public static final String SP1_CAR_REF_STRING = "CAR-Ref-String";

  public static final String SP1_CHR_REF_STRING = "CHR-Ref-String";

  @MockBean
  CvcTlsCheck cvcTlsCheck;

  @MockBean
  TerminalPermissionAOBean terminalPermissionAO;

  @MockBean
  PermissionDataHandling permissionDataHandling;

  @MockBean
  RequestSignerCertificateService rscService;

  @MockBean
  ConfigurationService configurationService;

  @MockBean
  TlsClientRenewalService tlsClientRenewalService;


  @Test
  void testWhenCvcTlsCheckEmptyThenStatusPageWithMessageAndNoValues() throws Exception
  {

    Mockito.when(cvcTlsCheck.check()).thenReturn(Optional.empty());

    HtmlPage loginPage = getWebClient().getPage(getRequestUrl(ContextPaths.DASHBOARD));
    HtmlPage statusPage = login(loginPage);

    assertMessageAlert(statusPage, "No status available because configuration is not valid.");
    Assertions.assertFalse(statusPage.asNormalizedText().contains("Start check"));
    Assertions.assertFalse(statusPage.asNormalizedText().contains("Status of eID service providers"));
  }

  @Test
  void testWhenCvcTlsHasResultThenStatusPageWithValues() throws Exception
  {
    String firstSp = "ServiceProviderTestA";
    String secondSp = "ServiceProviderTestB";
    CvcTlsCheck.CvcTlsCheckResult cvcTlsCheckResult = new CvcTlsCheck.CvcTlsCheckResult();
    cvcTlsCheckResult.setServerTlsValid(true);
    Date expectedDate = Date.from(Instant.now());
    cvcTlsCheckResult.setServerTlsExpirationDate(expectedDate);
    CvcTlsCheck.CvcCheckResults cvcCheckResultsFirstSp = new CvcTlsCheck.CvcCheckResults();
    cvcCheckResultsFirstSp.setCvcPresent(true);
    cvcCheckResultsFirstSp.setCvcTlsMatch(true);
    cvcCheckResultsFirstSp.setCvcValidity(true);
    cvcCheckResultsFirstSp.setCvcUrlMatch(true);
    Map<String, CvcTlsCheck.CvcCheckResults> providerCvcChecks = cvcTlsCheckResult.getProviderCvcChecks();
    providerCvcChecks.put(firstSp, cvcCheckResultsFirstSp);

    CvcTlsCheck.CvcCheckResults cvcCheckResultsSecondSp = new CvcTlsCheck.CvcCheckResults();
    cvcCheckResultsSecondSp.setCvcPresent(false);
    cvcCheckResultsSecondSp.setCvcTlsMatch(false);
    cvcCheckResultsSecondSp.setCvcValidity(false);
    cvcCheckResultsSecondSp.setCvcUrlMatch(false);
    providerCvcChecks.put(secondSp, cvcCheckResultsSecondSp);

    Mockito.when(configurationService.getConfiguration()).thenReturn(getConfiguration());
    Mockito.when(tlsClientRenewalService.currentTlsCertValidUntil(Mockito.anyString()))
           .thenReturn(Optional.of(new Date()));
    Mockito.when(cvcTlsCheck.check(Mockito.anyBoolean())).thenReturn(Optional.of(cvcTlsCheckResult));
    Mockito.when(cvcTlsCheck.checkCvcProvider(firstSp))
           .thenReturn(cvcTlsCheckResult.getProviderCvcChecks().get(firstSp));
    Mockito.when(cvcTlsCheck.checkCvcProvider(secondSp))
           .thenReturn(cvcTlsCheckResult.getProviderCvcChecks().get(secondSp));
    prepareFirstSp(firstSp, expectedDate);
    prepareSecondSp(secondSp);

    Mockito.when(permissionDataHandling.pingRIService(firstSp)).thenReturn(true);
    Mockito.when(permissionDataHandling.pingPAService(firstSp)).thenReturn(true);
    Mockito.when(permissionDataHandling.pingRIService(secondSp)).thenReturn(false);
    Mockito.when(permissionDataHandling.pingPAService(secondSp)).thenReturn(false);

    Mockito.when(rscService.getRequestSignerCertificate(firstSp, true)).thenReturn(getRsc());
    Mockito.when(rscService.getRequestSignerCertificate(firstSp, false)).thenReturn(null);
    Mockito.when(rscService.getRequestSignerCertificate(secondSp, true)).thenReturn(null);
    Mockito.when(rscService.getRequestSignerCertificate(secondSp, false)).thenReturn(getRsc());


    HtmlPage loginPage = getWebClient().getPage(getRequestUrl(ContextPaths.DASHBOARD));
    HtmlPage statusPage = login(loginPage);
    Assertions.assertTrue(statusPage.asNormalizedText().contains("Start check"));
    Assertions.assertTrue(statusPage.asNormalizedText().contains("Status of eID service providers"));
    DomElement serverTlsValid = statusPage.getElementById("serverTlsValid");
    String actualValueServerTlsValid = serverTlsValid.asNormalizedText();
    Assertions.assertEquals("Valid: ✔\n Expiration date:\n"
                            + expectedDate.toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime().toString(),
                            actualValueServerTlsValid);
    String crlAvailable = statusPage.getElementById("crlAvailable").asNormalizedText();
    // To test CRL available with last retrieval Powermock must be used.
    Assertions.assertEquals("Available: ❌\n Last successful retrieval:\n-", crlAvailable);
    assertFirstServiceProvider(statusPage.getElementById(firstSp), expectedDate);
    assertSecondServiceProvider(statusPage.getElementById(secondSp));
  }

  @Test
  void testWhenCvcTlsCheckResultHasRSACertWithLengthLowerThan3000Bits() throws Exception
  {
    String firstSp = "ServiceProviderTestA";
    CvcTlsCheck.CvcTlsCheckResult cvcTlsCheckResult = new CvcTlsCheck.CvcTlsCheckResult();
    cvcTlsCheckResult.setServerTlsValid(true);
    cvcTlsCheckResult.getTlsRSACertsWithLengthLowerThan3000().add("TLS server certificate");
    Date expectedDate = Date.from(Instant.now());
    cvcTlsCheckResult.setServerTlsExpirationDate(expectedDate);
    CvcTlsCheck.CvcCheckResults cvcCheckResultsFirstSp = new CvcTlsCheck.CvcCheckResults();
    cvcCheckResultsFirstSp.setCvcPresent(true);
    cvcCheckResultsFirstSp.setCvcTlsMatch(true);
    cvcCheckResultsFirstSp.setCvcValidity(true);
    cvcCheckResultsFirstSp.setCvcUrlMatch(true);
    Map<String, CvcTlsCheck.CvcCheckResults> providerCvcChecks = cvcTlsCheckResult.getProviderCvcChecks();
    providerCvcChecks.put(firstSp, cvcCheckResultsFirstSp);

    Optional<EidasMiddlewareConfig> configuration = getConfiguration();

    when(configurationService.getConfiguration()).thenReturn(configuration);
    when(tlsClientRenewalService.currentTlsCertValidUntil(Mockito.anyString())).thenReturn(Optional.of(new Date()));
    when(cvcTlsCheck.check(Mockito.anyBoolean())).thenReturn(Optional.of(cvcTlsCheckResult));
    when(cvcTlsCheck.checkCvcProvider(firstSp)).thenReturn(cvcTlsCheckResult.getProviderCvcChecks().get(firstSp));
    prepareFirstSp(firstSp, expectedDate);

    when(permissionDataHandling.pingRIService(firstSp)).thenReturn(true);
    when(permissionDataHandling.pingPAService(firstSp)).thenReturn(true);

    when(rscService.getRequestSignerCertificate(firstSp, true)).thenReturn(getRsc());
    when(rscService.getRequestSignerCertificate(firstSp, false)).thenReturn(null);

    HtmlPage loginPage = getWebClient().getPage(getRequestUrl(ContextPaths.DASHBOARD));
    HtmlPage dashboardPage = login(loginPage);

    if (dashboardPage.getByXPath("//div[contains(@class, 'alert-warning')]").isEmpty())
    {
      Assertions.fail("Expected at least one alert-warning div but got 0.");
    }
    else
    {
      List<String> dashboardAlertWarningChieldNodeFirstString = new ArrayList<>();
      List<HtmlDivision> dashboardAlertWarningHtmlDivision = dashboardPage.getByXPath("//div[contains(@class, 'alert-warning')]");
      for ( HtmlDivision htmlDivision : dashboardAlertWarningHtmlDivision )
      {
        dashboardAlertWarningChieldNodeFirstString.add(htmlDivision.getChildNodes().get(0).toString());
      }
      Assertions.assertTrue(dashboardAlertWarningChieldNodeFirstString.contains("The following TLS RSA certificates have a bit length lower than 3000:"));
    }
  }

  private void assertFirstServiceProvider(DomElement domElement, Date expectedDate)
  {
    // CVC
    NodeList cvcSpanValues = ((DomElement)domElement.getFirstByXPath(".//div[@id='cvc']")).getElementsByTagName("span");
    Assertions.assertEquals(8, cvcSpanValues.getLength());
    Assertions.assertEquals(OK, cvcSpanValues.item(0).getTextContent());
    Assertions.assertEquals(SP1_REF_ID, cvcSpanValues.item(1).getTextContent());
    Assertions.assertEquals(SP1_CHR_REF_STRING, cvcSpanValues.item(2).getTextContent());
    Assertions.assertEquals(SP1_CAR_REF_STRING, cvcSpanValues.item(3).getTextContent());
    Assertions.assertEquals(expectedDate.toInstant().atZone(ZoneId.systemDefault()).toLocalDate().toString(),
                            cvcSpanValues.item(4).getTextContent());
    Assertions.assertEquals(expectedDate.toInstant()
                                        .atZone(ZoneId.systemDefault())
                                        .toLocalDate()
                                        .minusDays(1)
                                        .toString(),
                            cvcSpanValues.item(5).getTextContent());
    Assertions.assertEquals(OK, cvcSpanValues.item(6).getTextContent());
    Assertions.assertEquals(OK, cvcSpanValues.item(7).getTextContent());

    // RSC
    DomNodeList<HtmlElement> rscSpanValues = ((DomElement)domElement.getFirstByXPath(".//div[@id='rsc']")).getElementsByTagName("span");
    Assertions.assertEquals(3, rscSpanValues.size());
    Assertions.assertEquals(OK, rscSpanValues.get(0).asNormalizedText());
    Assertions.assertEquals("2023-09-02", rscSpanValues.item(1).getTextContent());
    Assertions.assertEquals(NOT_OK, rscSpanValues.get(2).asNormalizedText());
    // Black List
    DomNodeList<HtmlElement> blackListValues = ((DomElement)domElement.getFirstByXPath(".//div[@id='blackList']")).getElementsByTagName("span");
    Assertions.assertEquals(3, blackListValues.size());
    Assertions.assertEquals(OK, blackListValues.get(0).asNormalizedText());
    Assertions.assertEquals(expectedDate.toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime().toString(),
                            blackListValues.item(1).getTextContent());
    Assertions.assertEquals(OK, blackListValues.get(2).asNormalizedText());
    // Master List
    DomNodeList<HtmlElement> masterListValues = ((DomElement)domElement.getFirstByXPath(".//div[@id='masterList']")).getElementsByTagName("span");
    Assertions.assertEquals(3, masterListValues.size());
    Assertions.assertEquals(OK, masterListValues.get(0).asNormalizedText());
    Assertions.assertEquals(expectedDate.toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime().toString(),
                            masterListValues.item(1).getTextContent());
    Assertions.assertEquals(OK, masterListValues.get(2).asNormalizedText());
    // Defect List
    DomNodeList<HtmlElement> defectListValues = ((DomElement)domElement.getFirstByXPath(".//div[@id='defectList']")).getElementsByTagName("span");
    Assertions.assertEquals(3, defectListValues.size());
    Assertions.assertEquals(OK, defectListValues.get(0).asNormalizedText());
    Assertions.assertEquals(expectedDate.toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime().toString(),
                            defectListValues.item(1).getTextContent());
    Assertions.assertEquals(OK, defectListValues.get(2).asNormalizedText());
  }

  private void assertSecondServiceProvider(DomElement domElement)
  {
    NodeList cvcSpanValues = ((DomElement)domElement.getFirstByXPath(".//div[@id='cvc']")).getElementsByTagName("span");
    Assertions.assertEquals(8, cvcSpanValues.getLength());
    Assertions.assertEquals(NOT_OK, cvcSpanValues.item(0).getTextContent());
    Assertions.assertEquals(NOT_PRESENT, cvcSpanValues.item(1).getTextContent());
    Assertions.assertEquals(NOT_PRESENT, cvcSpanValues.item(2).getTextContent());
    Assertions.assertEquals(NOT_PRESENT, cvcSpanValues.item(3).getTextContent());
    Assertions.assertEquals(NOT_PRESENT, cvcSpanValues.item(4).getTextContent());
    Assertions.assertEquals(NOT_PRESENT, cvcSpanValues.item(5).getTextContent());
    Assertions.assertEquals(NOT_PRESENT, cvcSpanValues.item(6).getTextContent());
    Assertions.assertEquals(NOT_PRESENT, cvcSpanValues.item(7).getTextContent());

    // RSC
    DomNodeList<HtmlElement> rscSpanValues = ((DomElement)domElement.getFirstByXPath(".//div[@id='rsc']")).getElementsByTagName("span");
    Assertions.assertEquals(3, rscSpanValues.size());
    Assertions.assertEquals(NOT_OK, rscSpanValues.get(0).asNormalizedText());
    Assertions.assertEquals(NOT_PRESENT, rscSpanValues.item(1).getTextContent());
    Assertions.assertEquals(OK, rscSpanValues.get(2).asNormalizedText());
    // Black List
    DomNodeList<HtmlElement> blackListValues = ((DomElement)domElement.getFirstByXPath(".//div[@id='blackList']")).getElementsByTagName("span");
    Assertions.assertEquals(3, blackListValues.size());
    Assertions.assertEquals(NOT_OK, blackListValues.get(0).asNormalizedText());
    Assertions.assertEquals(NOT_PRESENT, blackListValues.item(1).getTextContent());
    Assertions.assertEquals(NOT_OK, blackListValues.get(2).asNormalizedText());
    // Master List
    DomNodeList<HtmlElement> masterListValues = ((DomElement)domElement.getFirstByXPath(".//div[@id='masterList']")).getElementsByTagName("span");
    Assertions.assertEquals(3, masterListValues.size());
    Assertions.assertEquals(NOT_OK, masterListValues.get(0).asNormalizedText());
    Assertions.assertEquals(NOT_PRESENT, masterListValues.item(1).getTextContent());
    Assertions.assertEquals(NOT_OK, masterListValues.get(2).asNormalizedText());
    // Defect List
    DomNodeList<HtmlElement> defectListValues = ((DomElement)domElement.getFirstByXPath(".//div[@id='defectList']")).getElementsByTagName("span");
    Assertions.assertEquals(3, defectListValues.size());
    Assertions.assertEquals(NOT_OK, defectListValues.get(0).asNormalizedText());
    Assertions.assertEquals(NOT_PRESENT, defectListValues.item(1).getTextContent());
    Assertions.assertEquals(NOT_OK, defectListValues.get(2).asNormalizedText());
  }

  private void prepareFirstSp(String firstSp, Date expectedDate)
  {
    TerminalPermission terminalPermissionFirstSp = Mockito.mock(TerminalPermission.class);
    Mockito.when(terminalPermissionAO.getTerminalPermission(firstSp)).thenReturn(terminalPermissionFirstSp);
    Mockito.when(terminalPermissionFirstSp.getRefID()).thenReturn(SP1_REF_ID);
    Mockito.when(terminalPermissionFirstSp.getNotOnOrAfter()).thenReturn(expectedDate);
    Mockito.when(terminalPermissionFirstSp.getBlackListVersion()).thenReturn(1L);
    Mockito.when(terminalPermissionFirstSp.getBlackListStoreDate()).thenReturn(expectedDate);
    Mockito.when(terminalPermissionFirstSp.getMasterList()).thenReturn(ArrayUtils.EMPTY_BYTE_ARRAY);
    Mockito.when(terminalPermissionFirstSp.getMasterListStoreDate()).thenReturn(expectedDate);
    Mockito.when(terminalPermissionFirstSp.getDefectList()).thenReturn(ArrayUtils.EMPTY_BYTE_ARRAY);
    Mockito.when(terminalPermissionFirstSp.getDefectListStoreDate()).thenReturn(expectedDate);
    Mockito.when(terminalPermissionFirstSp.getCvcDescription()).thenReturn(Base64.getDecoder().decode(CVC_DESCRIPTION));
    TerminalData terminalData = Mockito.mock(TerminalData.class);
    Mockito.when(terminalPermissionFirstSp.getFullCvc()).thenReturn(terminalData);
    Mockito.when(terminalData.getCAReferenceString()).thenReturn(SP1_CAR_REF_STRING);
    Mockito.when(terminalData.getHolderReferenceString()).thenReturn(SP1_CHR_REF_STRING);
    // We can use any date here, because there is no comparison with the valid until date
    Mockito.when(terminalData.getEffectiveDate()).thenReturn(expectedDate);
  }

  private void prepareSecondSp(String secondSp)
  {
    TerminalPermission terminalPermissionSecondSp = Mockito.mock(TerminalPermission.class);
    Mockito.when(terminalPermissionAO.getTerminalPermission(secondSp)).thenReturn(terminalPermissionSecondSp);
    Mockito.when(terminalPermissionSecondSp.getNotOnOrAfter()).thenReturn(null);
    Mockito.when(terminalPermissionSecondSp.getBlackListVersion()).thenReturn(null);
    Mockito.when(terminalPermissionSecondSp.getBlackListStoreDate()).thenReturn(null);
    Mockito.when(terminalPermissionSecondSp.getMasterList()).thenReturn(null);
    Mockito.when(terminalPermissionSecondSp.getMasterListStoreDate()).thenReturn(null);
    Mockito.when(terminalPermissionSecondSp.getDefectList()).thenReturn(null);
    Mockito.when(terminalPermissionSecondSp.getDefectListStoreDate()).thenReturn(null);
    Mockito.when(terminalPermissionSecondSp.getCvcDescription()).thenReturn(null);
  }

  private X509Certificate getRsc() throws Exception
  {
    try (
      InputStream requestSignerCertificateAsInputStream = DashboardControllerTest.class.getResourceAsStream("/requestSigner.cer");)
    {
      CertificateFactory x509certificateFactory = CertificateFactory.getInstance("X509",
                                                                                 SecurityProvider.BOUNCY_CASTLE_PROVIDER);
      return (X509Certificate)x509certificateFactory.generateCertificate(requestSignerCertificateAsInputStream);
    }
  }

  private Optional<EidasMiddlewareConfig> getConfiguration()
  {
    EidasMiddlewareConfig eidasMiddlewareConfig = new EidasMiddlewareConfig();
    EidasMiddlewareConfig.EidConfiguration eidConfiguration = new EidasMiddlewareConfig.EidConfiguration();
    ServiceProviderType firstServiceProviderType = new ServiceProviderType("ServiceProviderTestA", true,
                                                                           "ServiceProviderTestA", "dvcaConf",
                                                                           "clientKeyPair", null);
    ServiceProviderType secondServiceProviderType = new ServiceProviderType("ServiceProviderTestB", true,
                                                                            "ServiceProviderTestB", "dvcaConf",
                                                                            "clientKeyPair", null);
    eidConfiguration.getServiceProvider().add(firstServiceProviderType);
    eidConfiguration.getServiceProvider().add(secondServiceProviderType);
    eidasMiddlewareConfig.setEidConfiguration(eidConfiguration);
    return Optional.of(eidasMiddlewareConfig);
  }
}

/*
 * Copyright (c) 2022 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.config;

import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.gargoylesoftware.htmlunit.UnexpectedPage;
import com.gargoylesoftware.htmlunit.html.DomNode;
import com.gargoylesoftware.htmlunit.html.DomText;
import com.gargoylesoftware.htmlunit.html.HtmlDivision;
import com.gargoylesoftware.htmlunit.html.HtmlPage;

import de.governikus.eumw.poseidas.config.base.TestConfiguration;
import de.governikus.eumw.poseidas.config.model.ServiceProviderStatus;
import de.governikus.eumw.poseidas.gov2server.constants.admin.GlobalManagementCodes;
import de.governikus.eumw.poseidas.server.pki.RequestSignerCertificateService;
import de.governikus.eumw.poseidas.server.pki.ServiceProviderStatusService;
import de.governikus.eumw.utils.key.SecurityProvider;


@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {"server.servlet.context-path=/"})
@Import(TestConfiguration.class)
@DisplayName("Test the detail page")
class CVCControllerTest extends ServiceProviderTestBase
{

  @MockBean
  RequestSignerCertificateService requestSignerCertificateService;

  @MockBean
  ServiceProviderStatusService serviceProviderStatusService;

  private ServiceProviderStatus serviceProviderStatus;


  @BeforeEach
  public void setUp() throws Exception
  {
    Mockito.when(configurationService.getConfiguration()).thenReturn(createConfiguration());
    Mockito.when(data.getPermissionDataInfo(Mockito.anyString(), Mockito.anyBoolean()))
           .thenReturn(createPermissionDataInfo());
    serviceProviderStatus = createServiceProviderStatus();
    Mockito.when(serviceProviderStatusService.getServiceProviderStatus(Mockito.any()))
           .thenReturn(serviceProviderStatus);
  }

  private HtmlPage getServiceProviderPage() throws IOException
  {
    HtmlPage loginPage = getWebClient().getPage(getRequestUrl("/details?entityid="
                                                              + ServiceProviderTestBase.SERVICE_PROVIDER));
    return login(loginPage);
  }

  @Test
  void testCheckSuccessful() throws IOException
  {
    Mockito.when(data.checkReadyForFirstRequest(Mockito.anyString()))
           .thenReturn(GlobalManagementCodes.OK.createMessage());

    HtmlPage serviceProvider = getServiceProviderPage();
    HtmlPage checkedPage = (HtmlPage)click(serviceProvider, "check-button");
    assertMessageAlert(checkedPage, "Connection check succeeded");
  }

  @Test
  void testCheckFailed() throws IOException
  {
    Mockito.when(data.checkReadyForFirstRequest(Mockito.anyString()))
           .thenReturn(GlobalManagementCodes.INTERNAL_ERROR.createMessage());

    HtmlPage serviceProvider = getServiceProviderPage();
    HtmlPage checkedPage = (HtmlPage)click(serviceProvider, "check-button");
    assertErrorAlert(checkedPage, "Connection check failed: ");
  }

  @Test
  void testServiceProviderInfo() throws IOException
  {
    HtmlPage serviceProvider = getServiceProviderPage();
    List<HtmlDivision> serviceProviderInfo = serviceProvider.getByXPath("//div[contains(@class, 'cvcInfoBox')]");
    Map<String, String> cvcInfo = new HashMap<>();
    for ( HtmlDivision htmlDivision : serviceProviderInfo )
    {
      getInfoFromTable(cvcInfo, htmlDivision);
    }
    Assertions.assertEquals(10, cvcInfo.size());
    Assertions.assertEquals(INFO_MAP.get(CHR), cvcInfo.get(CHR));
    Assertions.assertEquals(INFO_MAP.get(CAR), cvcInfo.get(CAR));
    Assertions.assertEquals(INFO_MAP.get(VALID_FROM), cvcInfo.get(VALID_FROM));
    Assertions.assertEquals(INFO_MAP.get(VALID_UNTIL), cvcInfo.get(VALID_UNTIL));
    Assertions.assertEquals(INFO_MAP.get(TERMS_OF_USAGE), cvcInfo.get(TERMS_OF_USAGE));
    Assertions.assertEquals(INFO_MAP.get(REDIRECT_URL), cvcInfo.get(REDIRECT_URL));
    Assertions.assertEquals(INFO_MAP.get(SUBJECT), cvcInfo.get(SUBJECT));
    Assertions.assertEquals(INFO_MAP.get(SUBJECT_URL), cvcInfo.get(SUBJECT_URL));
    Assertions.assertEquals(INFO_MAP.get(ISSUER), cvcInfo.get(ISSUER));
    Assertions.assertEquals(INFO_MAP.get(ISSUER_URL), cvcInfo.get(ISSUER_URL));
  }

  private void getInfoFromTable(Map<String, String> infoMap, HtmlDivision infoDivCol)
  {
    List<DomNode> childNodes = infoDivCol.getChildNodes()
                                         .stream()
                                         .filter(element -> !(element instanceof DomText))
                                         .collect(Collectors.toList());
    for ( int i = 1 ; i < childNodes.size() ; i = i + 2 )
    {
      infoMap.put(childNodes.get(i - 1).asNormalizedText(), childNodes.get(i).asNormalizedText());
    }
  }

  @Test
  void testRenewCVCSuccess() throws IOException
  {
    Mockito.when(data.triggerCertRenewal(Mockito.anyString())).thenReturn(GlobalManagementCodes.OK.createMessage());

    HtmlPage serviceProvider = getServiceProviderPage();
    HtmlPage renewedCvcPage = (HtmlPage)click(serviceProvider, "renew-cvc-button");
    assertMessageAlert(renewedCvcPage, "Renew CVC succeeded");
  }

  @Test
  void testRenewCVCFailure() throws IOException
  {
    Mockito.when(data.triggerCertRenewal(Mockito.anyString()))
           .thenReturn(GlobalManagementCodes.INTERNAL_ERROR.createMessage());

    HtmlPage serviceProvider = getServiceProviderPage();
    HtmlPage renewedCvcPage = (HtmlPage)click(serviceProvider, "renew-cvc-button");
    assertErrorAlert(renewedCvcPage, "Renew CVC failed: CO.msg.error.internalError");
  }

  @Test
  void testInitialRequestSuccess() throws IOException
  {
    Mockito.when(data.requestFirstTerminalCertificate(Mockito.anyString(),
                                                      Mockito.anyString(),
                                                      Mockito.anyString(),
                                                      Mockito.anyInt()))
           .thenAnswer(invocation -> {
             String entityId = invocation.getArgument(0, String.class);
             String countryCode = invocation.getArgument(1, String.class);
             String chr = invocation.getArgument(2, String.class);
             int sequenceNumber = invocation.getArgument(3, Integer.class);

             Assertions.assertEquals(SERVICE_PROVIDER, entityId);
             Assertions.assertEquals("DE", countryCode);
             Assertions.assertEquals("CHR", chr);
             Assertions.assertEquals(42, sequenceNumber);

             return GlobalManagementCodes.OK.createMessage();
           });

    HtmlPage serviceProviderPage = getServiceProviderPage();
    setTextValue(serviceProviderPage, "countryCode", "DE");
    setTextValue(serviceProviderPage, "chrMnemonic", "CHR");
    setNumberValue(serviceProviderPage, "sequenceNumber", 42);
    HtmlPage requestedCvcPage = submitFormById(serviceProviderPage, "initial-request-form");
    assertMessageAlert(requestedCvcPage, "Initial request succeeded");
  }

  @Test
  void testInitialRequestFailed() throws IOException
  {
    Mockito.when(data.requestFirstTerminalCertificate(Mockito.anyString(),
                                                      Mockito.anyString(),
                                                      Mockito.anyString(),
                                                      Mockito.anyInt()))
           .thenReturn(GlobalManagementCodes.INTERNAL_ERROR.createMessage());

    HtmlPage serviceProviderPage = getServiceProviderPage();
    setTextValue(serviceProviderPage, "countryCode", "DE");
    setTextValue(serviceProviderPage, "chrMnemonic", "CHR");
    setNumberValue(serviceProviderPage, "sequenceNumber", 42);
    HtmlPage requestedCvcPage = submitFormById(serviceProviderPage, "initial-request-form");
    assertErrorAlert(requestedCvcPage, "Initial request failed");
  }

  @Test
  void testGenerateRSCSuccess() throws IOException
  {
    HtmlPage serviceProviderPage = getServiceProviderPage();
    // Check the data for no RSC
    HtmlDivision rscInfoTable = (HtmlDivision)serviceProviderPage.getElementById("rsc-info-table");
    Map<String, String> rscInfoMap = new HashMap<>();
    getInfoFromTable(rscInfoMap, rscInfoTable);
    Assertions.assertEquals(3, rscInfoMap.size());
    Assertions.assertEquals("❌", rscInfoMap.get("Is RSC in use:"));
    Assertions.assertEquals("❌", rscInfoMap.get("RSC pending"));
    Assertions.assertEquals("", rscInfoMap.get("Valid until:"));

    // Generate RSC and check data again
    Mockito.when(requestSignerCertificateService.generateNewPendingRequestSignerCertificate(Mockito.anyString(),
                                                                                            Mockito.isNull(),
                                                                                            Mockito.anyInt()))
           .thenReturn(true);
    ServiceProviderStatus serviceProviderStatus = ServiceProviderStatus.builder()
                                                                       .rscAnyPresent(true)
                                                                       .rscPendingPresent(true)
                                                                       .build();
    Mockito.when(serviceProviderStatusService.getServiceProviderStatus(Mockito.any()))
           .thenReturn(serviceProviderStatus);

    HtmlPage generatedRSCPage = submitFormById(serviceProviderPage, "generate-rsc-form");
    rscInfoTable = (HtmlDivision)generatedRSCPage.getElementById("rsc-info-table");
    getInfoFromTable(rscInfoMap, rscInfoTable);
    Assertions.assertEquals(3, rscInfoMap.size());
    Assertions.assertEquals("❌", rscInfoMap.get("Is RSC in use:"));
    Assertions.assertEquals("✔", rscInfoMap.get("RSC pending"));
    Assertions.assertEquals("", rscInfoMap.get("Valid until:"));
    assertMessageAlert(generatedRSCPage, "Request signer certificate successfully created");
    Mockito.verify(requestSignerCertificateService, Mockito.atLeastOnce())
           .generateNewPendingRequestSignerCertificate(Mockito.anyString(), Mockito.isNull(), Mockito.anyInt());

    // Now mock that the pending RSC changed state to current
    LocalDate now = LocalDate.now();
    serviceProviderStatus = ServiceProviderStatus.builder()
                                                 .rscAnyPresent(true)
                                                 .rscPendingPresent(false)
                                                 .rscCurrentValidUntil(now)
                                                 .build();
    Mockito.when(serviceProviderStatusService.getServiceProviderStatus(Mockito.any()))
           .thenReturn(serviceProviderStatus);

    HtmlPage currentRscPage = getWebClient().getPage(getRequestUrl("/details?entityid="
                                                                   + ServiceProviderTestBase.SERVICE_PROVIDER));
    rscInfoTable = (HtmlDivision)currentRscPage.getElementById("rsc-info-table");
    getInfoFromTable(rscInfoMap, rscInfoTable);
    Assertions.assertEquals(3, rscInfoMap.size());
    Assertions.assertEquals("✔", rscInfoMap.get("Is RSC in use:"));
    Assertions.assertEquals("❌", rscInfoMap.get("RSC pending"));
    Assertions.assertEquals(now.format(DateTimeFormatter.ISO_DATE), rscInfoMap.get("Valid until:"));
  }

  @Test
  void testGenerateRSCFailed() throws Exception
  {
    HtmlPage serviceProviderPage = getServiceProviderPage();
    // Generate RSC will throw an error
    HtmlPage generatedRSCPage = submitFormById(serviceProviderPage, "generate-rsc-form");
    assertErrorAlert(generatedRSCPage, "Creation of request signer certificate failed");
  }

  @Test
  void testDownloadRSCFailed() throws IOException
  {
    ServiceProviderStatus serviceProviderStatus = ServiceProviderStatus.builder().rscAnyPresent(true).build();
    Mockito.when(serviceProviderStatusService.getServiceProviderStatus(Mockito.any()))
           .thenReturn(serviceProviderStatus);

    HtmlPage serviceProviderPage = getServiceProviderPage();
    HtmlPage downloadedRscPage = (HtmlPage)click(serviceProviderPage, "download-rsc-button");
    assertErrorAlert(downloadedRscPage, "Download of request signer certificate failed. Please check your log.");
  }

  @Test
  void testDownloadRSCReturnsRSCAsX509() throws Exception
  {
    InputStream requestSignerCertificateAsInputStream = CVCControllerTest.class.getResourceAsStream("/requestSigner.cer");
    CertificateFactory x509certificateFactory = CertificateFactory.getInstance("X509",
                                                                               SecurityProvider.BOUNCY_CASTLE_PROVIDER);
    X509Certificate requestSignerCertificate = (X509Certificate)x509certificateFactory.generateCertificate(requestSignerCertificateAsInputStream);
    ServiceProviderStatus serviceProviderStatus = ServiceProviderStatus.builder().rscAnyPresent(true).build();
    Mockito.when(serviceProviderStatusService.getServiceProviderStatus(Mockito.any()))
           .thenReturn(serviceProviderStatus);
    Mockito.when(requestSignerCertificateService.getRequestSignerCertificate(Mockito.anyString()))
           .thenReturn(requestSignerCertificate);

    HtmlPage serviceProviderPage = getServiceProviderPage();
    UnexpectedPage downloadedRscPage = (UnexpectedPage)click(serviceProviderPage, "download-rsc-button");
    Assertions.assertEquals(MediaType.APPLICATION_OCTET_STREAM_VALUE,
                            downloadedRscPage.getWebResponse().getResponseHeaderValue("Content-Type"));
    Assertions.assertEquals("attachment; filename=\"CN=DEeIDAS-DE00001.cer\"",
                            downloadedRscPage.getWebResponse().getResponseHeaderValue("Content-Disposition"));
    Assertions.assertArrayEquals(requestSignerCertificate.getEncoded(),
                                 downloadedRscPage.getWebResponse().getContentAsStream().readAllBytes());
  }

  @Test
  void testListsInfo() throws IOException
  {
    HtmlPage serviceProviderPage = getServiceProviderPage();
    Map<String, String> listInfoMap = new HashMap<>();
    String lastRenewal = serviceProviderStatus.getBlackListLastRetrieval()
                                              .format(DateTimeFormatter.ofPattern("uuuu-MM-dd'T'HH:mm:ss"));

    // Check black list info
    HtmlDivision blackListInfo = (HtmlDivision)serviceProviderPage.getElementById("black-list-info");
    getInfoFromTable(listInfoMap, blackListInfo);
    Assertions.assertEquals(3, listInfoMap.size());
    Assertions.assertEquals("✔", listInfoMap.get("Available:"));
    Assertions.assertEquals(lastRenewal, trimDate(listInfoMap.get("Last renewal:")));
    Assertions.assertEquals("✔", listInfoMap.get("CA reachable:"));

    // Check master list info
    HtmlDivision masterListInfo = (HtmlDivision)serviceProviderPage.getElementById("master-list-info");
    getInfoFromTable(listInfoMap, masterListInfo);
    Assertions.assertEquals(3, listInfoMap.size());
    Assertions.assertEquals("✔", listInfoMap.get("Available:"));
    Assertions.assertEquals(lastRenewal, trimDate(listInfoMap.get("Last renewal:")));
    Assertions.assertEquals("✔", listInfoMap.get("CA reachable:"));

    // Check defect list info
    HtmlDivision defectListInfo = (HtmlDivision)serviceProviderPage.getElementById("defect-list-info");
    getInfoFromTable(listInfoMap, defectListInfo);
    Assertions.assertEquals(3, listInfoMap.size());
    Assertions.assertEquals("✔", listInfoMap.get("Available:"));
    Assertions.assertEquals(lastRenewal, trimDate(listInfoMap.get("Last renewal:")));
    Assertions.assertEquals("✔", listInfoMap.get("CA reachable:"));
  }

  /**
   * Remove the milliseconds from the timestamp
   */
  private String trimDate(String date)
  {
    return date.substring(0, 19);
  }

  @Test
  void testBlackListRenewalSuccess() throws IOException
  {
    Mockito.when(data.renewBlackList(Mockito.anyString())).thenReturn(GlobalManagementCodes.OK.createMessage());

    HtmlPage serviceProviderPage = getServiceProviderPage();
    HtmlPage renewedBlackListPage = (HtmlPage)click(serviceProviderPage, "renew-blacklist-button");
    assertMessageAlert(renewedBlackListPage, "Renew black list succeeded");
  }

  @Test
  void testBlackListRenewalFailed() throws IOException
  {
    Mockito.when(data.renewBlackList(Mockito.anyString()))
           .thenReturn(GlobalManagementCodes.INTERNAL_ERROR.createMessage());

    HtmlPage serviceProviderPage = getServiceProviderPage();
    HtmlPage renewedBlackListPage = (HtmlPage)click(serviceProviderPage, "renew-blacklist-button");
    assertErrorAlert(renewedBlackListPage, "Renew black list failed: ");
  }

  @Test
  void testMasterDefectListRenewalSuccess() throws IOException
  {
    Mockito.when(data.renewMasterAndDefectList(Mockito.anyString()))
           .thenReturn(GlobalManagementCodes.OK.createMessage());

    HtmlPage serviceProviderPage = getServiceProviderPage();
    HtmlPage renewedBlackListPage = (HtmlPage)click(serviceProviderPage, "renew-masterdefectlist-button");
    assertMessageAlert(renewedBlackListPage, "Renew Master and Defect List succeeded");
  }

  @Test
  void testMasterDefectListRenewalFailed() throws IOException
  {
    Mockito.when(data.renewMasterAndDefectList(Mockito.anyString()))
           .thenReturn(GlobalManagementCodes.INTERNAL_ERROR.createMessage());

    HtmlPage serviceProviderPage = getServiceProviderPage();
    HtmlPage renewedBlackListPage = (HtmlPage)click(serviceProviderPage, "renew-masterdefectlist-button");
    assertErrorAlert(renewedBlackListPage, "Renew Master and Defect List failed: ");
  }
}

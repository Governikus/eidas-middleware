/*
 * Copyright (c) 2022 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.config;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Optional;

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
import com.gargoylesoftware.htmlunit.html.HtmlAnchor;
import com.gargoylesoftware.htmlunit.html.HtmlDivision;
import com.gargoylesoftware.htmlunit.html.HtmlListItem;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import com.gargoylesoftware.htmlunit.html.HtmlParagraph;
import com.gargoylesoftware.htmlunit.html.HtmlSpan;
import com.gargoylesoftware.htmlunit.html.HtmlTableRow;
import com.gargoylesoftware.htmlunit.html.HtmlTextArea;

import de.governikus.eumw.config.CertificateType;
import de.governikus.eumw.config.EidasMiddlewareConfig;
import de.governikus.eumw.poseidas.config.base.TestConfiguration;
import de.governikus.eumw.poseidas.service.MetadataService;
import de.governikus.eumw.utils.key.KeyReader;
import lombok.SneakyThrows;


@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {"server.servlet.context-path=/"})
@Import(TestConfiguration.class)
@DisplayName("Test the metadata page")
class MetadataControllerTest extends ServiceProviderTestBase
{

  @MockBean
  MetadataService metadataService;

  @SneakyThrows
  @BeforeEach
  void setupMocks()
  {
    // Two metadata entries
    Mockito.when(configurationService.getConfiguration()).thenReturn(createConfiguration());

    // Certificate must be mocked separately
    X509Certificate certificate = KeyReader.readX509Certificate(MetadataControllerTest.class.getResourceAsStream("/configuration/sigCert.crt"));
    Mockito.when(configurationService.getCertificate(Mockito.anyString())).thenReturn(certificate);

    // And again
    Mockito.when(configurationService.getCertificateTypes())
           .thenReturn(List.of(new CertificateType("sigCert", certificate.getEncoded(), null, null)));
  }

  @Test
  void testMetadataTable() throws IOException
  {
    HtmlPage loginPage = getWebClient().getPage(getRequestUrl("/metadataConfig"));
    HtmlPage metadataPage = login(loginPage);

    HtmlTableRow demoEpa = (HtmlTableRow)metadataPage.getElementById("entry-0");
    Assertions.assertEquals("https://demo.mein-servicekonto.de/EidasNode/ConnectorMetadata?SP=demo_epa",
                            getSpanText(demoEpa, "entityId"));
    Assertions.assertEquals("✔", getSpanText(demoEpa, "signatureValid"));

    HtmlTableRow demoEpaInvalid = (HtmlTableRow)metadataPage.getElementById("entry-1");
    Assertions.assertEquals("https://demo.mein-servicekonto.de/EidasNode/ConnectorMetadata?SP=demo_epa_invalid",
                            getSpanText(demoEpaInvalid, "entityId"));
    Assertions.assertEquals("❌", getSpanText(demoEpaInvalid, "signatureValid"));
  }

  private String getSpanText(HtmlTableRow tableRow, String spanId)
  {
    return ((HtmlSpan)tableRow.getFirstByXPath(".//span[@id='" + spanId + "']")).getTextContent();
  }

  @Test
  void testDelete() throws IOException
  {
    HtmlPage loginPage = getWebClient().getPage(getRequestUrl("/metadataConfig"));
    HtmlPage metadataPage = login(loginPage);

    // Click on delete for demo_epa_invalid
    HtmlTableRow demoEpaInvalid = (HtmlTableRow)metadataPage.getElementById("entry-1");
    List<HtmlAnchor> anchors = demoEpaInvalid.getByXPath(".//a");
    Assertions.assertEquals(2, anchors.size());
    Assertions.assertTrue(anchors.get(1).getHrefAttribute().contains("/remove"));
    HtmlPage removePage = anchors.get(1).click();

    // Check the confirmation page and actually delete the metadata
    HtmlDivision cardBody = removePage.getFirstByXPath("//div[@class=('card-body')]");
    HtmlParagraph paragraph = cardBody.getFirstByXPath(".//p");
    Assertions.assertTrue(paragraph.asNormalizedText()
                                   .contains("https://demo.mein-servicekonto.de/EidasNode/ConnectorMetadata?SP=demo_epa_invalid"));
    HtmlTextArea textarea = cardBody.getFirstByXPath("//textarea");
    Assertions.assertEquals(new String(MetadataControllerTest.class.getResourceAsStream("/configuration/demo_epa_invalid.xml")
                                                                   .readAllBytes(),
                                       StandardCharsets.UTF_8),
                            textarea.getText());
    HtmlPage afterDeletion = (HtmlPage)click(removePage, "delete");

    // Check that the deletion was successful
    assertMessageAlert(afterDeletion,
                       "Metadata file removed: https://demo.mein-servicekonto.de/EidasNode/ConnectorMetadata?SP=demo_epa_invalid");
    HtmlTableRow demoEpa = (HtmlTableRow)afterDeletion.getElementById("entry-0");
    Assertions.assertEquals("https://demo.mein-servicekonto.de/EidasNode/ConnectorMetadata?SP=demo_epa",
                            getSpanText(demoEpa, "entityId"));
    Assertions.assertNull(afterDeletion.getElementById("entry-1"));
  }

  @Test
  void testConnectorMetadataDownload() throws IOException
  {
    HtmlPage loginPage = getWebClient().getPage(getRequestUrl("/metadataConfig"));
    HtmlPage metadataPage = login(loginPage);

    // Click on download for demo_epa
    HtmlTableRow demoEpaInvalid = (HtmlTableRow)metadataPage.getElementById("entry-0");
    List<HtmlAnchor> anchors = demoEpaInvalid.getByXPath(".//a");
    Assertions.assertEquals(2, anchors.size());
    Assertions.assertTrue(anchors.get(0).getHrefAttribute().contains("/download"));
    UnexpectedPage downloadPage = anchors.get(0).click();

    // Check the response
    Assertions.assertEquals(MediaType.APPLICATION_OCTET_STREAM_VALUE,
                            downloadPage.getWebResponse().getResponseHeaderValue("Content-Type"));
    Assertions.assertEquals("attachment; filename=Metadata.xml",
                            downloadPage.getWebResponse().getResponseHeaderValue("Content-Disposition"));
    Assertions.assertArrayEquals(ServiceProviderTestBase.class.getResourceAsStream("/configuration/demo_epa.xml")
                                                              .readAllBytes(),
                                 downloadPage.getInputStream().readAllBytes());
  }

  @Test
  void testUpload() throws IOException
  {
    HtmlPage loginPage = getWebClient().getPage(getRequestUrl("/metadataConfig"));
    HtmlPage metadataPage = login(loginPage);

    // Upload a third file
    File demoEpa20File = new File(MetadataControllerTest.class.getResource("/configuration/demo_epa_20.xml").getPath());
    setFileUpload(metadataPage, "metadataFile", demoEpa20File);
    HtmlPage afterUploadPage = submitFormById(metadataPage, "uploadMetadata");

    // Check the content
    assertMessageAlert(afterUploadPage, "Metadata file uploaded successfully");
    HtmlTableRow demoEpa = (HtmlTableRow)afterUploadPage.getElementById("entry-0");
    Assertions.assertEquals("https://demo.mein-servicekonto.de/EidasNode/ConnectorMetadata?SP=demo_epa",
                            getSpanText(demoEpa, "entityId"));
    Assertions.assertEquals("✔", getSpanText(demoEpa, "signatureValid"));

    HtmlTableRow demoEpa20 = (HtmlTableRow)afterUploadPage.getElementById("entry-1");
    Assertions.assertEquals("https://demo.mein-servicekonto.de/EidasNode/ConnectorMetadata?SP=demo_epa_20",
                            getSpanText(demoEpa20, "entityId"));
    Assertions.assertEquals("✔", getSpanText(demoEpa20, "signatureValid"));

    HtmlTableRow demoEpaInvalid = (HtmlTableRow)afterUploadPage.getElementById("entry-2");
    Assertions.assertEquals("https://demo.mein-servicekonto.de/EidasNode/ConnectorMetadata?SP=demo_epa_invalid",
                            getSpanText(demoEpaInvalid, "entityId"));
    Assertions.assertEquals("❌", getSpanText(demoEpaInvalid, "signatureValid"));
  }

  @Test
  void testMiddlewareMetadataDownload() throws IOException
  {
    byte[] metadataBytes = MetadataControllerTest.class.getResourceAsStream("/Metadata.xml").readAllBytes();
    Mockito.when(metadataService.getMetadata()).thenReturn(metadataBytes);

    HtmlPage loginPage = getWebClient().getPage(getRequestUrl("/metadataConfig"));
    HtmlPage metadataPage = login(loginPage);

    // Click the link in the nav bar to download the middleware metadat
    List<HtmlListItem> navItems = metadataPage.getByXPath("//li[@class=('nav-item')]");
    HtmlListItem downloadMetadata = navItems.stream()
                                            .filter(htmlListItem -> htmlListItem.asNormalizedText()
                                                                                .contains("Download metadata"))
                                            .findFirst()
                                            .orElseThrow();
    UnexpectedPage downloadPage = downloadMetadata.getFirstElementChild().click();
    // Check the response
    Assertions.assertEquals(MediaType.APPLICATION_OCTET_STREAM_VALUE,
                            downloadPage.getWebResponse().getResponseHeaderValue("Content-Type"));
    Assertions.assertEquals("attachment; filename=Metadata.xml",
                            downloadPage.getWebResponse().getResponseHeaderValue("Content-Disposition"));
    Assertions.assertArrayEquals(metadataBytes, downloadPage.getInputStream().readAllBytes());
  }

  @Test
  void testChangeCertificate() throws IOException
  {
    // Mock configuration with two certificates
    Optional<EidasMiddlewareConfig> configuration = createConfiguration();
    configuration.get()
                 .getKeyData()
                 .getCertificate()
                 .add((new CertificateType("jks-keystore",
                                           ServiceProviderTestBase.class.getResourceAsStream("/configuration/jks-keystore.cer")
                                                                        .readAllBytes(),
                                           null, null)));
    Mockito.when(configurationService.getConfiguration()).thenReturn(configuration);

    // And again
    Mockito.when(configurationService.getCertificateTypes())
           .thenReturn(configuration.get().getKeyData().getCertificate());

    // And again
    Mockito.when(configurationService.getCertificate(Mockito.anyString())).thenAnswer(invocation -> {
      String certificateName = invocation.getArgument(0, String.class);
      if (certificateName.equals("jks-keystore"))
      {
        return KeyReader.readX509Certificate(configuration.get().getKeyData().getCertificate().get(1).getCertificate());
      }
      else
      {
        return KeyReader.readX509Certificate(configuration.get().getKeyData().getCertificate().get(0).getCertificate());
      }
    });

    // Open page, change certificate
    HtmlPage loginPage = getWebClient().getPage(getRequestUrl("/metadataConfig"));
    HtmlPage metadataPage = login(loginPage);
    setSelectValue(metadataPage, "metadataSignatureVerificationCertificateName", "jks-keystore");
    HtmlPage changedCertificatePage = submitFormById(metadataPage, "metadataSignatureVerificationCertificate");

    // Check content
    Assertions.assertTrue(changedCertificatePage.asNormalizedText().contains("jks-keystore"));
    Assertions.assertFalse(changedCertificatePage.asNormalizedText().contains("sigCert"));

    HtmlTableRow demoEpa = (HtmlTableRow)changedCertificatePage.getElementById("entry-0");
    Assertions.assertEquals("https://demo.mein-servicekonto.de/EidasNode/ConnectorMetadata?SP=demo_epa",
                            getSpanText(demoEpa, "entityId"));
    Assertions.assertEquals("❌", getSpanText(demoEpa, "signatureValid"));

    HtmlTableRow demoEpaInvalid = (HtmlTableRow)changedCertificatePage.getElementById("entry-1");
    Assertions.assertEquals("https://demo.mein-servicekonto.de/EidasNode/ConnectorMetadata?SP=demo_epa_invalid",
                            getSpanText(demoEpaInvalid, "entityId"));
    Assertions.assertEquals("❌", getSpanText(demoEpaInvalid, "signatureValid"));
  }
}

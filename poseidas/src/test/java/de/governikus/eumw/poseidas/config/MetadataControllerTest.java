/*
 * Copyright (c) 2022 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.config;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.commons.lang3.ArrayUtils;
import org.apache.xml.security.algorithms.MessageDigestAlgorithm;
import org.apache.xml.security.signature.XMLSignature;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mockito;
import org.opensaml.saml.common.SAMLObjectContentReference;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.ext.saml2alg.SigningMethod;
import org.opensaml.saml.ext.saml2alg.impl.SigningMethodBuilder;
import org.opensaml.saml.saml2.core.NameIDType;
import org.opensaml.saml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml.saml2.metadata.EncryptionMethod;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.Extensions;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.saml2.metadata.NameIDFormat;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml.saml2.metadata.impl.AssertionConsumerServiceBuilder;
import org.opensaml.saml.saml2.metadata.impl.EncryptionMethodBuilder;
import org.opensaml.saml.saml2.metadata.impl.EntityDescriptorBuilder;
import org.opensaml.saml.saml2.metadata.impl.EntityDescriptorMarshaller;
import org.opensaml.saml.saml2.metadata.impl.ExtensionsBuilder;
import org.opensaml.saml.saml2.metadata.impl.KeyDescriptorBuilder;
import org.opensaml.saml.saml2.metadata.impl.NameIDFormatBuilder;
import org.opensaml.saml.saml2.metadata.impl.SPSSODescriptorBuilder;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.encryption.support.EncryptionConstants;
import org.opensaml.xmlsec.signature.DigestMethod;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.X509Data;
import org.opensaml.xmlsec.signature.impl.DigestMethodBuilder;
import org.opensaml.xmlsec.signature.impl.KeyInfoBuilder;
import org.opensaml.xmlsec.signature.impl.SignatureBuilder;
import org.opensaml.xmlsec.signature.impl.X509CertificateBuilder;
import org.opensaml.xmlsec.signature.impl.X509DataBuilder;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.Signer;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.w3c.dom.Element;

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
import de.governikus.eumw.config.ConnectorMetadataType;
import de.governikus.eumw.config.EidasMiddlewareConfig;
import de.governikus.eumw.eidascommon.Utils;
import de.governikus.eumw.eidasstarterkit.EidasSaml;
import de.governikus.eumw.poseidas.config.base.TestConfiguration;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationException;
import de.governikus.eumw.poseidas.service.MetadataService;
import de.governikus.eumw.utils.key.KeyReader;
import de.governikus.eumw.utils.key.KeyStoreSupporter;
import lombok.SneakyThrows;
import se.swedenconnect.opensaml.eidas.ext.NodeCountry;
import se.swedenconnect.opensaml.eidas.ext.SPType;
import se.swedenconnect.opensaml.eidas.ext.SPTypeEnumeration;
import se.swedenconnect.opensaml.eidas.ext.impl.NodeCountryBuilder;
import se.swedenconnect.opensaml.eidas.ext.impl.SPTypeBuilder;


@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {"server.servlet.context-path=/"})
@Import(TestConfiguration.class)
@DisplayName("Test the metadata page")
class MetadataControllerTest extends ServiceProviderTestBase
{

  public static final String INVALID_METADATA_VERIFICATION_CERTIFICATE_NAME = "invalidMetadataVerificationCertificate";

  @MockBean
  MetadataService metadataService;

  @SneakyThrows
  @BeforeEach
  void setupMocks()
  {
    // Two metadata entries
    Mockito.when(configurationService.getConfiguration()).thenReturn(createConfiguration());

    // Certificate must be mocked separately
    X509Certificate certificate = KeyReader.readX509Certificate(MetadataControllerTest.class.getResourceAsStream("/configuration/metadata-signer.cer"));
    Mockito.when(configurationService.getSamlCertificate("sigCert")).thenReturn(certificate);
    Mockito.when(configurationService.getCertificate("sigCert")).thenReturn(certificate);

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
    Assertions.assertEquals("https://localhost:9443/eIDASDemoApplication/Metadata", getSpanText(demoEpa, "entityId"));
    Assertions.assertEquals("✔", getSpanText(demoEpa, "signatureValid"));

    HtmlTableRow demoEpaInvalid = (HtmlTableRow)metadataPage.getElementById("entry-1");
    Assertions.assertEquals("https://localhost:9445/eIDASDemoApplication/Metadata",
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

    // Click on delete for localhost:8445
    HtmlTableRow invalidMetadata = (HtmlTableRow)metadataPage.getElementById("entry-1");
    List<HtmlAnchor> anchors = invalidMetadata.getByXPath(".//a");
    Assertions.assertEquals(2, anchors.size());
    Assertions.assertTrue(anchors.get(1).getHrefAttribute().contains("/remove"));
    HtmlPage removePage = anchors.get(1).click();

    // Check the confirmation page and actually delete the metadata
    HtmlDivision cardBody = removePage.getFirstByXPath("//div[@class=('card-body')]");
    HtmlParagraph paragraph = cardBody.getFirstByXPath(".//p");
    Assertions.assertTrue(paragraph.asNormalizedText()
                                   .contains("https://localhost:9445/eIDASDemoApplication/Metadata"));
    HtmlTextArea textarea = cardBody.getFirstByXPath("//textarea");
    Assertions.assertEquals(new String(MetadataControllerTest.class.getResourceAsStream("/configuration/metadata-9445-invalid.xml")
                                                                   .readAllBytes(),
                                       StandardCharsets.UTF_8),
                            textarea.getText());
    HtmlPage afterDeletion = (HtmlPage)click(removePage, "delete");

    // Check that the deletion was successful
    assertMessageAlert(afterDeletion, "Metadata file removed: https://localhost:9445/eIDASDemoApplication/Metadata");
    HtmlTableRow validMetadata = (HtmlTableRow)afterDeletion.getElementById("entry-0");
    Assertions.assertEquals("https://localhost:9443/eIDASDemoApplication/Metadata",
                            getSpanText(validMetadata, "entityId"));
    Assertions.assertNull(afterDeletion.getElementById("entry-1"));
  }

  @Test
  void testConnectorMetadataDownload() throws IOException
  {
    HtmlPage loginPage = getWebClient().getPage(getRequestUrl("/metadataConfig"));
    HtmlPage metadataPage = login(loginPage);

    // Click on download for demo_epa
    HtmlTableRow validMetadata = (HtmlTableRow)metadataPage.getElementById("entry-0");
    List<HtmlAnchor> anchors = validMetadata.getByXPath(".//a");
    Assertions.assertEquals(2, anchors.size());
    Assertions.assertTrue(anchors.get(0).getHrefAttribute().contains("/download"));
    UnexpectedPage downloadPage = anchors.get(0).click();

    // Check the response
    Assertions.assertEquals(MediaType.APPLICATION_OCTET_STREAM_VALUE,
                            downloadPage.getWebResponse().getResponseHeaderValue("Content-Type"));
    Assertions.assertEquals("attachment; filename=Metadata.xml",
                            downloadPage.getWebResponse().getResponseHeaderValue("Content-Disposition"));
    Assertions.assertArrayEquals(ServiceProviderTestBase.class.getResourceAsStream("/configuration/metadata-9443.xml")
                                                              .readAllBytes(),
                                 downloadPage.getInputStream().readAllBytes());
  }

  @Test
  void testUpload() throws IOException
  {
    HtmlPage loginPage = getWebClient().getPage(getRequestUrl("/metadataConfig"));
    HtmlPage metadataPage = login(loginPage);

    // Upload a third file
    File demoEpa20File = new File(MetadataControllerTest.class.getResource("/configuration/metadata-9444.xml")
                                                              .getPath());
    setFileUpload(metadataPage, "metadataFile", demoEpa20File);
    HtmlPage afterUploadPage = submitFormById(metadataPage, "uploadMetadata");

    // Check the content
    assertMessageAlert(afterUploadPage, "Metadata file uploaded successfully");
    HtmlTableRow demoEpa = (HtmlTableRow)afterUploadPage.getElementById("entry-0");
    Assertions.assertEquals("https://localhost:9443/eIDASDemoApplication/Metadata", getSpanText(demoEpa, "entityId"));
    Assertions.assertEquals("✔", getSpanText(demoEpa, "signatureValid"));

    HtmlTableRow demoEpa20 = (HtmlTableRow)afterUploadPage.getElementById("entry-1");
    Assertions.assertEquals("https://localhost:9444/eIDASDemoApplication/Metadata", getSpanText(demoEpa20, "entityId"));
    Assertions.assertEquals("✔", getSpanText(demoEpa20, "signatureValid"));

    HtmlTableRow demoEpaInvalid = (HtmlTableRow)afterUploadPage.getElementById("entry-2");
    Assertions.assertEquals("https://localhost:9445/eIDASDemoApplication/Metadata",
                            getSpanText(demoEpaInvalid, "entityId"));
    Assertions.assertEquals("❌", getSpanText(demoEpaInvalid, "signatureValid"));
  }

  @ParameterizedTest
  @ValueSource(strings = {"/configuration/metadata-9444-shortcrypt-ec.xml",
                          "/configuration/metadata-9444-shortsign-ec.xml"})
  void testUploadShortCertsEc(String metaFile) throws IOException
  {
    HtmlPage loginPage = getWebClient().getPage(getRequestUrl("/metadataConfig"));
    HtmlPage metadataPage = login(loginPage);

    // Upload a file with short EC key
    File demoEpa20File = new File(MetadataControllerTest.class.getResource(metaFile).getPath());
    setFileUpload(metadataPage, "metadataFile", demoEpa20File);
    HtmlPage afterUploadPage = submitFormById(metadataPage, "uploadMetadata");

    // Check the content
    assertMessageAlert(afterUploadPage,
                       "Certificate is not valid for that purpose because of reason Certificate with subject CN=Wurst, OU=Autent A, O=Governikus, L=Bremen, ST=Bremen, C=DE and serial 1701967321 does not meet specified minimum EC key size of 256.");
    HtmlTableRow demoEpa = (HtmlTableRow)afterUploadPage.getElementById("entry-0");
    Assertions.assertEquals("https://localhost:9443/eIDASDemoApplication/Metadata", getSpanText(demoEpa, "entityId"));
    Assertions.assertEquals("✔", getSpanText(demoEpa, "signatureValid"));

    HtmlTableRow demoEpaInvalid = (HtmlTableRow)afterUploadPage.getElementById("entry-1");
    Assertions.assertEquals("https://localhost:9445/eIDASDemoApplication/Metadata",
                            getSpanText(demoEpaInvalid, "entityId"));
    Assertions.assertEquals("❌", getSpanText(demoEpaInvalid, "signatureValid"));

    // Assert no more metadata are in the HTML Table
    Assertions.assertNull(afterUploadPage.getElementById("entry-2"));
  }

  @ParameterizedTest
  @ValueSource(strings = {"/configuration/metadata-9444-shortcrypt-rsa.xml",
                          "/configuration/metadata-9444-shortsign-rsa.xml"})
  void testUploadShortCertsRsa(String metaFile) throws IOException
  {
    HtmlPage loginPage = getWebClient().getPage(getRequestUrl("/metadataConfig"));
    HtmlPage metadataPage = login(loginPage);

    // Upload a file with short RSA key
    File demoEpa20File = new File(MetadataControllerTest.class.getResource(metaFile).getPath());
    setFileUpload(metadataPage, "metadataFile", demoEpa20File);
    HtmlPage afterUploadPage = submitFormById(metadataPage, "uploadMetadata");

    // Check the content
    assertMessageAlert(afterUploadPage,
                       "Certificate is not valid for that purpose because of reason Certificate with subject CN=Wurst, OU=Autent A, O=Governikus, L=Bremen, ST=Bremen, C=DE and serial 1701967541 does not meet specified minimum RSA key size of 3072.");
    HtmlTableRow demoEpa = (HtmlTableRow)afterUploadPage.getElementById("entry-0");
    Assertions.assertEquals("https://localhost:9443/eIDASDemoApplication/Metadata", getSpanText(demoEpa, "entityId"));
    Assertions.assertEquals("✔", getSpanText(demoEpa, "signatureValid"));

    HtmlTableRow demoEpaInvalid = (HtmlTableRow)afterUploadPage.getElementById("entry-1");
    Assertions.assertEquals("https://localhost:9445/eIDASDemoApplication/Metadata",
                            getSpanText(demoEpaInvalid, "entityId"));
    Assertions.assertEquals("❌", getSpanText(demoEpaInvalid, "signatureValid"));

    // Assert no more metadata are in the HTML Table
    Assertions.assertNull(afterUploadPage.getElementById("entry-2"));
  }

  @ParameterizedTest
  @ValueSource(strings = {"/configuration/metadata-9444-explicit-crypt.xml",
                          "/configuration/metadata-9444-explicit-sign.xml"})
  void testUploadExplicitCerts(String metaFile) throws IOException
  {
    HtmlPage loginPage = getWebClient().getPage(getRequestUrl("/metadataConfig"));
    HtmlPage metadataPage = login(loginPage);

    // Upload a file with short RSA key
    File demoEpa20File = new File(MetadataControllerTest.class.getResource(metaFile).getPath());
    setFileUpload(metadataPage, "metadataFile", demoEpa20File);
    HtmlPage afterUploadPage = submitFormById(metadataPage, "uploadMetadata");

    // Check the content
    assertMessageAlert(afterUploadPage,
                       "Certificate is not valid for that purpose because of reason Certificate with subject CN=TEST csca-germany, OU=bsi, O=bund, C=DE and serial 1264 does not use a named curve.");
    HtmlTableRow demoEpa = (HtmlTableRow)afterUploadPage.getElementById("entry-0");
    Assertions.assertEquals("https://localhost:9443/eIDASDemoApplication/Metadata", getSpanText(demoEpa, "entityId"));
    Assertions.assertEquals("✔", getSpanText(demoEpa, "signatureValid"));

    HtmlTableRow demoEpaInvalid = (HtmlTableRow)afterUploadPage.getElementById("entry-1");
    Assertions.assertEquals("https://localhost:9445/eIDASDemoApplication/Metadata",
                            getSpanText(demoEpaInvalid, "entityId"));
    Assertions.assertEquals("❌", getSpanText(demoEpaInvalid, "signatureValid"));

    // Assert no more metadata are in the HTML Table
    Assertions.assertNull(afterUploadPage.getElementById("entry-2"));
  }

  @Test
  void testMiddlewareMetadataDownload() throws IOException
  {
    byte[] metadataBytes = MetadataControllerTest.class.getResourceAsStream("/Metadata.xml").readAllBytes();
    Mockito.when(metadataService.getMetadata()).thenReturn(metadataBytes);

    HtmlPage loginPage = getWebClient().getPage(getRequestUrl("/metadataConfig"));
    HtmlPage metadataPage = login(loginPage);

    // Click the link in the nav bar to download the middleware metadata
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
    Mockito.when(configurationService.getSamlCertificate(Mockito.anyString())).thenAnswer(invocation -> {
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
    Assertions.assertEquals("https://localhost:9443/eIDASDemoApplication/Metadata", getSpanText(demoEpa, "entityId"));
    Assertions.assertEquals("❌", getSpanText(demoEpa, "signatureValid"));

    HtmlTableRow demoEpaInvalid = (HtmlTableRow)changedCertificatePage.getElementById("entry-1");
    Assertions.assertEquals("https://localhost:9445/eIDASDemoApplication/Metadata",
                            getSpanText(demoEpaInvalid, "entityId"));
    Assertions.assertEquals("❌", getSpanText(demoEpaInvalid, "signatureValid"));
  }

  @Test
  void testWhenChangeMetadataVerificationCertificateTooShortThenShowError() throws Exception
  {
    // Override Mocks from SetUp Method
    EidasMiddlewareConfig configuration = createConfiguration().orElseThrow();
    // Add dummy cert to key data.
    configuration.getKeyData()
                 .getCertificate()
                 .add(new CertificateType(INVALID_METADATA_VERIFICATION_CERTIFICATE_NAME, ArrayUtils.EMPTY_BYTE_ARRAY,
                                          null,
                                          null));
    // Override mock calls from setUp method, otherwise a configuration without the dummy certificate type will be
    // returned
    Mockito.when(configurationService.getConfiguration()).thenReturn(Optional.of(configuration));
    Mockito.when(configurationService.getCertificateTypes()).thenReturn(configuration.getKeyData().getCertificate());
    // Mock the call when the dummy cert key size is checked
    Mockito.when(configurationService.getSamlCertificate(INVALID_METADATA_VERIFICATION_CERTIFICATE_NAME))
           .thenThrow(ConfigurationException.class);

    // Actual calls to the endpoints
    HtmlPage loginPage = getWebClient().getPage(getRequestUrl("/metadataConfig"));
    HtmlPage metadataPage = login(loginPage);
    // Select dummy cert
    setSelectValue(metadataPage,
                   "metadataSignatureVerificationCertificateName",
                   INVALID_METADATA_VERIFICATION_CERTIFICATE_NAME);
    HtmlPage changedCertificatePage = submitFormById(metadataPage, "metadataSignatureVerificationCertificate");
    // Verify that the expected error message is displayed and the config is not changed
    assertErrorAlert(changedCertificatePage,
                     "Cannot save the selected metadata verification certificate: ");
    Mockito.verify(configurationService, Mockito.never()).saveConfiguration(configuration, false);

    // Verify that the metadata are still present and the signature is valid
    HtmlTableRow demoEpa = (HtmlTableRow)changedCertificatePage.getElementById("entry-0");
    Assertions.assertEquals("https://localhost:9443/eIDASDemoApplication/Metadata", getSpanText(demoEpa, "entityId"));
    Assertions.assertEquals("✔", getSpanText(demoEpa, "signatureValid"));

    HtmlTableRow demoEpaInvalid = (HtmlTableRow)changedCertificatePage.getElementById("entry-1");
    Assertions.assertEquals("https://localhost:9445/eIDASDemoApplication/Metadata",
                            getSpanText(demoEpaInvalid, "entityId"));
    Assertions.assertEquals("❌", getSpanText(demoEpaInvalid, "signatureValid"));
  }

  @ParameterizedTest
  @MethodSource("testSha1Metadata")
  void testInvalidAlgorithmMetadataSignature(String signatureAlgorithm,
                                             String digestAlgorithm,
                                             String keyStorePath,
                                             String alias,
                                             @TempDir Path tempDir)
    throws Exception
  {
    File file = cretaeEntityDescriptorWithSignatureFile(signatureAlgorithm,
                                                        digestAlgorithm,
                                                        keyStorePath,
                                                        alias,
                                                        tempDir);

    HtmlPage loginPage = getWebClient().getPage(getRequestUrl("/metadataConfig"));
    HtmlPage metadataPage = login(loginPage);

    // Upload a metadata file with an invalid digest algorithm or an invalid signature algorithm
    setFileUpload(metadataPage, "metadataFile", file);
    HtmlPage afterUploadPage = submitFormById(metadataPage, "uploadMetadata");

    // Check the error message
    assertMessageAlert(afterUploadPage, "Invalid hash or signature algorithm");

    // Check that the other metadata files still available
    HtmlTableRow demoEpa20 = (HtmlTableRow)afterUploadPage.getElementById("entry-0");
    Assertions.assertEquals("https://localhost:9443/eIDASDemoApplication/Metadata", getSpanText(demoEpa20, "entityId"));
    Assertions.assertEquals("✔", getSpanText(demoEpa20, "signatureValid"));

    HtmlTableRow demoEpaInvalid = (HtmlTableRow)afterUploadPage.getElementById("entry-1");
    Assertions.assertEquals("https://localhost:9445/eIDASDemoApplication/Metadata",
                            getSpanText(demoEpaInvalid, "entityId"));
    Assertions.assertEquals("❌", getSpanText(demoEpaInvalid, "signatureValid"));

    // Assert no more metadata are in the HTML Table
    Assertions.assertNull(afterUploadPage.getElementById("entry-2"));
  }

  @ParameterizedTest
  @MethodSource("testSha1Metadata")
  void testInvalidAlgorithmInMetadataSignatureAlreadyInConfigPresent(String signatureAlgorithm,
                                                                     String digestAlgorithm,
                                                                     String keyStorePath,
                                                                     String alias)
    throws Exception
  {
    ConnectorMetadataType connectorMetadataType = new ConnectorMetadataType();
    connectorMetadataType.setEntityID("InvalidDigestAlgOrSigAlg");
    String signedEntityDesriptor = getSignedEntityDescriptor(signatureAlgorithm, digestAlgorithm, keyStorePath, alias);
    connectorMetadataType.setValue(signedEntityDesriptor.getBytes(StandardCharsets.UTF_8));
    configurationService.getConfiguration()
                        .orElseThrow()
                        .getEidasConfiguration()
                        .getConnectorMetadata()
                        .add(connectorMetadataType);

    HtmlPage loginPage = getWebClient().getPage(getRequestUrl("/metadataConfig"));
    HtmlPage metadataPage = login(loginPage);

    // Check the error message
    assertErrorAlert(metadataPage,
                     "Cannot parse already saved metadata with entityId InvalidDigestAlgOrSigAlg. "
                                   + "This metadata is not usable by the middleware and must be deleted or replaced. "
                                   + "See the log of the middleware for more details.");
    // Check that the other metadata files still available
    HtmlTableRow invalidMetadataSignature = (HtmlTableRow)metadataPage.getElementById("entry-0");
    Assertions.assertEquals("InvalidDigestAlgOrSigAlg", getSpanText(invalidMetadataSignature, "entityId"));
    Assertions.assertEquals("❌", getSpanText(invalidMetadataSignature, "signatureValid"));

    HtmlTableRow demoEpa20 = (HtmlTableRow)metadataPage.getElementById("entry-1");
    Assertions.assertEquals("https://localhost:9443/eIDASDemoApplication/Metadata", getSpanText(demoEpa20, "entityId"));
    Assertions.assertEquals("✔", getSpanText(demoEpa20, "signatureValid"));

    HtmlTableRow demoEpaInvalid = (HtmlTableRow)metadataPage.getElementById("entry-2");
    Assertions.assertEquals("https://localhost:9445/eIDASDemoApplication/Metadata",
                            getSpanText(demoEpaInvalid, "entityId"));
    Assertions.assertEquals("❌", getSpanText(demoEpaInvalid, "signatureValid"));

    // Assert no more metadata are in the HTML Table
    Assertions.assertNull(metadataPage.getElementById("entry-3"));
  }

  @Test
  void testCurrentMetadataVerificationCertificateNotValid() throws Exception
  {
    EidasMiddlewareConfig configuration = configurationService.getConfiguration().orElseThrow();
    configuration.getEidasConfiguration()
                 .setMetadataSignatureVerificationCertificateName(INVALID_METADATA_VERIFICATION_CERTIFICATE_NAME);

    Mockito.when(configurationService.getSamlCertificate(INVALID_METADATA_VERIFICATION_CERTIFICATE_NAME))
           .thenThrow(ConfigurationException.class);
    Mockito.when(configurationService.getCertificate(INVALID_METADATA_VERIFICATION_CERTIFICATE_NAME))
           .thenThrow(ConfigurationException.class);

    HtmlPage loginPage = getWebClient().getPage(getRequestUrl("/metadataConfig"));
    HtmlPage metadataPage = login(loginPage);
    // Check the message
    assertErrorAlert(metadataPage, "The currently selected metadata verification certificate is not valid:");

    // Check that the other metadata files still available but without a valid signature
    HtmlTableRow demoEpa20 = (HtmlTableRow)metadataPage.getElementById("entry-0");
    Assertions.assertEquals("https://localhost:9443/eIDASDemoApplication/Metadata", getSpanText(demoEpa20, "entityId"));
    Assertions.assertEquals("❌", getSpanText(demoEpa20, "signatureValid"));

    HtmlTableRow demoEpaInvalid = (HtmlTableRow)metadataPage.getElementById("entry-1");
    Assertions.assertEquals("https://localhost:9445/eIDASDemoApplication/Metadata",
                            getSpanText(demoEpaInvalid, "entityId"));
    Assertions.assertEquals("❌", getSpanText(demoEpaInvalid, "signatureValid"));

    // Assert no more metadata are in the HTML Table
    Assertions.assertNull(metadataPage.getElementById("entry-2"));
  }

  static Stream<Arguments> testSha1Metadata()
  {
    return Stream.of(Arguments.of(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1_MGF1,
                                  SignatureConstants.ALGO_ID_DIGEST_SHA1,
                                  "/keys/bos-test-tctoken.saml-sign.p12",
                                  "bos-test-tctoken.saml-sign"),
                     Arguments.of(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256_MGF1,
                                  SignatureConstants.ALGO_ID_DIGEST_SHA1,
                                  "/keys/bos-test-tctoken.saml-sign.p12",
                                  "bos-test-tctoken.saml-sign"),
                     Arguments.of(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1_MGF1,
                                  SignatureConstants.ALGO_ID_DIGEST_SHA256,
                                  "/keys/bos-test-tctoken.saml-sign.p12",
                                  "bos-test-tctoken.saml-sign"),
                     Arguments.of(XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA1,
                                  SignatureConstants.ALGO_ID_DIGEST_SHA1,
                                  "/keys/ecc2.p12",
                                  "ec_nist_p256"),
                     Arguments.of(XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256,
                                  SignatureConstants.ALGO_ID_DIGEST_SHA1,
                                  "/keys/ecc2.p12",
                                  "ec_nist_p256"),
                     Arguments.of(XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA1,
                                  SignatureConstants.ALGO_ID_DIGEST_SHA256,
                                  "/keys/ecc2.p12",
                                  "ec_nist_p256"));
  }

  private File cretaeEntityDescriptorWithSignatureFile(String sigAlg,
                                                       String digestAlg,
                                                       String keyStorePath,
                                                       String alias,
                                                       Path tempDir)
    throws Exception
  {
    String metadataAsString = getSignedEntityDescriptor(sigAlg, digestAlg, keyStorePath, alias);

    Path tempMetadaFile = tempDir.resolve("tempMetadaFile");
    Path write = Files.writeString(tempMetadaFile, metadataAsString);

    return write.toFile();
  }

  private String getSignedEntityDescriptor(String sigAlg, String digestAlg, String keyStorePath, String alias)
    throws Exception
  {
    EidasSaml.init();
    EntityDescriptor entityDescriptor = new EntityDescriptorBuilder().buildObject();
    entityDescriptor.setEntityID("InvalidDigestAlgOrSigAlg");
    entityDescriptor.setValidUntil(Instant.now().plus(30, ChronoUnit.DAYS));
    SPSSODescriptor spssoDescriptor = new SPSSODescriptorBuilder().buildObject();
    Extensions extensions = new ExtensionsBuilder().buildObject();
    NodeCountry nc = new NodeCountryBuilder().buildObject();
    nc.setNodeCountry("SE");
    extensions.getUnknownXMLObjects().add(nc);
    spssoDescriptor.setExtensions(extensions);
    spssoDescriptor.setAuthnRequestsSigned(true);
    spssoDescriptor.setWantAssertionsSigned(false);
    spssoDescriptor.addSupportedProtocol(SAMLConstants.SAML20P_NS);

    addCerts(spssoDescriptor, configurationService.getCertificate("sigCert"));
    NameIDFormat persistent = new NameIDFormatBuilder().buildObject();
    persistent.setURI(NameIDType.PERSISTENT);
    spssoDescriptor.getNameIDFormats().add(persistent);

    NameIDFormat trans = new NameIDFormatBuilder().buildObject();
    trans.setURI(NameIDType.TRANSIENT);
    spssoDescriptor.getNameIDFormats().add(trans);

    NameIDFormat unspecified = new NameIDFormatBuilder().buildObject();
    unspecified.setURI(NameIDType.UNSPECIFIED);
    spssoDescriptor.getNameIDFormats().add(unspecified);

    AssertionConsumerService assertionConsumerService = new AssertionConsumerServiceBuilder().buildObject();
    assertionConsumerService.setBinding(SAMLConstants.SAML2_POST_BINDING_URI);
    assertionConsumerService.setLocation("https://dummmy-url.de");
    assertionConsumerService.setIsDefault(true);
    spssoDescriptor.getAssertionConsumerServices().add(assertionConsumerService);
    extensions = new ExtensionsBuilder().buildObject();

    SPType spType = new SPTypeBuilder().buildObject();
    spType.setType(SPTypeEnumeration.PUBLIC);
    extensions.getUnknownXMLObjects().add(spType);

    DigestMethod digestMethod = new DigestMethodBuilder().buildObject();
    digestMethod.setAlgorithm(MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA256);
    extensions.getUnknownXMLObjects().add(digestMethod);

    SigningMethod signingMethodRSA = new SigningMethodBuilder().buildObject();
    signingMethodRSA.setAlgorithm(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256_MGF1);
    signingMethodRSA.setMinKeySize(3072);
    signingMethodRSA.setMaxKeySize(4096);
    extensions.getUnknownXMLObjects().add(signingMethodRSA);

    entityDescriptor.getRoleDescriptors().add(spssoDescriptor);
    addSignature(entityDescriptor, digestAlg, sigAlg, keyStorePath, alias);
    return marshallMetadata(entityDescriptor);
  }

  private void addSignature(EntityDescriptor entityDescriptor,
                            String digestAlg,
                            String sigAlg,
                            String keyStorePath,
                            String alias)
    throws Exception
  {
    Signature signature = new SignatureBuilder().buildObject();
    File keystoreFile = new File(MetadataControllerTest.class.getResource(keyStorePath).toURI());
    KeyStore keyStore = KeyStoreSupporter.readKeyStore(keystoreFile, "123456");
    PrivateKey privateKey = (PrivateKey)keyStore.getKey(alias, "123456".toCharArray());
    X509Certificate certificate = (X509Certificate)keyStore.getCertificate(alias);
    BasicX509Credential credential = new BasicX509Credential(certificate, privateKey);
    signature.setSigningCredential(credential);
    signature.setSignatureAlgorithm(sigAlg);
    signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
    org.opensaml.xmlsec.signature.X509Certificate x509CertificateSignature = new X509CertificateBuilder().buildObject();
    x509CertificateSignature.setValue(Base64.getEncoder().encodeToString(certificate.getEncoded()));
    X509Data x509DataSignature = new X509DataBuilder().buildObject();
    x509DataSignature.getX509Certificates().add(x509CertificateSignature);
    KeyInfo keyInfoSignature = new KeyInfoBuilder().buildObject();
    keyInfoSignature.getX509Datas().add(x509DataSignature);
    signature.setKeyInfo(keyInfoSignature);
    entityDescriptor.setSignature(signature);
    ((SAMLObjectContentReference)signature.getContentReferences().get(0)).setDigestAlgorithm(digestAlg);
  }

  private void addCerts(SPSSODescriptor spssoDescriptor, X509Certificate cert) throws Exception
  {
    KeyDescriptor keyDescriptorSigning = new KeyDescriptorBuilder().buildObject();
    keyDescriptorSigning.setUse(UsageType.SIGNING);
    org.opensaml.xmlsec.signature.X509Certificate x509CertificateSigning = new X509CertificateBuilder().buildObject();
    x509CertificateSigning.setValue(Base64.getEncoder().encodeToString(cert.getEncoded()));
    X509Data x509DataSigning = new X509DataBuilder().buildObject();
    x509DataSigning.getX509Certificates().add(x509CertificateSigning);
    KeyInfo keyInfoSigning = new KeyInfoBuilder().buildObject();
    keyInfoSigning.getX509Datas().add(x509DataSigning);
    keyDescriptorSigning.setKeyInfo(keyInfoSigning);
    spssoDescriptor.getKeyDescriptors().add(keyDescriptorSigning);

    KeyDescriptor keyDescriptorEncryption = new KeyDescriptorBuilder().buildObject();
    keyDescriptorEncryption.setUse(UsageType.ENCRYPTION);
    org.opensaml.xmlsec.signature.X509Certificate x509CertificateEncryption = new X509CertificateBuilder().buildObject();
    x509CertificateEncryption.setValue(Base64.getEncoder().encodeToString(cert.getEncoded()));
    X509Data x509DataEncryption = new X509DataBuilder().buildObject();
    x509DataEncryption.getX509Certificates().add(x509CertificateEncryption);
    KeyInfo keyInfoEncryption = new KeyInfoBuilder().buildObject();
    keyInfoEncryption.getX509Datas().add(x509DataEncryption);
    keyDescriptorEncryption.setKeyInfo(keyInfoEncryption);

    EncryptionMethod encryptionMethod = new EncryptionMethodBuilder().buildObject();
    encryptionMethod.setAlgorithm(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128_GCM);
    keyDescriptorEncryption.getEncryptionMethods().add(encryptionMethod);
    encryptionMethod = new EncryptionMethodBuilder().buildObject();
    encryptionMethod.setAlgorithm(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES256_GCM);
    keyDescriptorEncryption.getEncryptionMethods().add(encryptionMethod);
    spssoDescriptor.getKeyDescriptors().add(keyDescriptorEncryption);
  }

  private String marshallMetadata(EntityDescriptor entityDescriptor) throws Exception
  {
    EntityDescriptorMarshaller marshaller = new EntityDescriptorMarshaller();
    Element all = null;
    all = marshaller.marshall(entityDescriptor);
    Signer.signObject(entityDescriptor.getSignature());

    try (ByteArrayOutputStream stream = new ByteArrayOutputStream())
    {
      Transformer transformer = Utils.getTransformer();
      transformer.setOutputProperty(OutputKeys.ENCODING, StandardCharsets.UTF_8.displayName());
      transformer.transform(new DOMSource(all), new StreamResult(stream));
      return stream.toString(StandardCharsets.UTF_8);
    }
  }
}

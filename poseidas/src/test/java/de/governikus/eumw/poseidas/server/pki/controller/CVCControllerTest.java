/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.pki.controller;

import java.io.InputStream;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.ui.Model;
import org.springframework.validation.support.BindingAwareModelMap;

import com.google.common.io.ByteStreams;

import de.governikus.eumw.poseidas.cardbase.ArrayUtil;
import de.governikus.eumw.poseidas.server.exception.MetadataDownloadException;
import de.governikus.eumw.poseidas.server.exception.RequestSignerDownloadException;
import de.governikus.eumw.poseidas.server.idprovider.config.CvcTlsCheck;
import de.governikus.eumw.poseidas.server.pki.PermissionDataHandlingMBean;
import de.governikus.eumw.poseidas.server.pki.RequestSignerCertificateService;
import de.governikus.eumw.poseidas.server.pki.model.CVCRequestModel;
import de.governikus.eumw.poseidas.service.MetadataService;


class CVCControllerTest
{

  CVCController controller;

  PermissionDataHandlingMBean data;

  MetadataService metadataService;

  CvcTlsCheck cvcTlsCheck;

  RequestSignerCertificateService requestSignerCertificateService;

  @BeforeEach
  public void setUp()
  {
    Security.addProvider(new BouncyCastleProvider());
    Path resourceDirectory = Paths.get("src", "test", "resources");
    System.setProperty("spring.config.additional-location", resourceDirectory.toFile().getAbsolutePath());
    data = Mockito.mock(PermissionDataHandlingMBean.class);
    metadataService = Mockito.mock(MetadataService.class);
    requestSignerCertificateService = Mockito.mock(RequestSignerCertificateService.class);
    controller = new CVCController(data, metadataService, cvcTlsCheck, requestSignerCertificateService);
  }

  @AfterAll
  public static void afterAll()
  {
    System.clearProperty("spring.config.additional-location");
  }

  @Test
  void metadataDownloadExceptionIsThrownWhenByteArrayIsEmpty()
  {
    byte[] bytes = new byte[0];
    Mockito.when(metadataService.getMetadata()).thenReturn(bytes);
    Assertions.assertThrows(MetadataDownloadException.class, () -> controller.downloadMetadata());
  }

  @Test
  void downloadMetadataReturnsMetadataAsXMLFile() throws Exception
  {
    InputStream resourceAsStream = CVCControllerTest.class.getResourceAsStream("/Metadata.xml");
    Mockito.when(metadataService.getMetadata()).thenReturn(ByteStreams.toByteArray(resourceAsStream));
    ResponseEntity<byte[]> responseEntity = controller.downloadMetadata();

    HttpStatus statusCode = responseEntity.getStatusCode();
    Assertions.assertEquals(HttpStatus.OK, statusCode);
    HttpHeaders headers = responseEntity.getHeaders();
    ContentDisposition contentDisposition = headers.getContentDisposition();
    Assertions.assertEquals("attachment", contentDisposition.getType());
    Assertions.assertEquals("Metadata.xml", contentDisposition.getFilename());
    Assertions.assertEquals(MediaType.APPLICATION_OCTET_STREAM, headers.getContentType());
    byte[] body = responseEntity.getBody();
    Assertions.assertFalse(ArrayUtil.isNullOrEmpty(body));
  }

  @Test
  void testGenerateRSCSuccess()
  {
    String entityID = "testProvider";
    Mockito.when(requestSignerCertificateService.generateNewPendingRequestSignerCertificate(Mockito.anyString(),
                                                                                            Mockito.anyString(),
                                                                                            Mockito.anyInt()))
           .thenReturn(true);
    Model model = new BindingAwareModelMap();
    CVCRequestModel cvcRequestModel = new CVCRequestModel();
    cvcRequestModel.setRscChr("test");
    controller.generateRSC(entityID, model, cvcRequestModel);
    Assertions.assertTrue(model.containsAttribute("success"));
    Assertions.assertTrue(model.containsAttribute("resultMessage"));
    Assertions.assertEquals("Request signer certificate successfully created",
                            model.getAttribute("resultMessage"));
  }

  @Test
  void testGenerateRSCFalse() throws Exception
  {
    String entityID = "testProvider";
    Mockito.when(requestSignerCertificateService.generateNewPendingRequestSignerCertificate(Mockito.anyString(),
                                                                                            Mockito.anyString(),
                                                                                            Mockito.anyInt()))
           .thenReturn(false);
    Model model = new BindingAwareModelMap();
    controller.generateRSC(entityID, model, new CVCRequestModel());
    Assertions.assertTrue(model.containsAttribute("error"));
    Assertions.assertTrue(model.containsAttribute("resultMessage"));
    Assertions.assertEquals("Creation of request signer certificate failed",
                            model.getAttribute("resultMessage"));
  }

  @Test
  void testRequestDownloadExceptionIsThrownWhenByteArrayIsEmpty()
  {
    Mockito.when(requestSignerCertificateService.getRequestSignerCertificate(Mockito.anyString()))
           .thenReturn(null);
    Assertions.assertThrows(RequestSignerDownloadException.class,
                            () -> controller.downloadRequestSignerCertificate(Mockito.anyString()));
  }

  @Test
  void testDownloadRSCReturnsRSCAsX509() throws Exception
  {
    InputStream requestSignerCertificateAsInputStream = CVCControllerTest.class.getResourceAsStream("/requestSigner.cer");
    CertificateFactory x509certificateFactory = CertificateFactory.getInstance("X509",
                                                                               BouncyCastleProvider.PROVIDER_NAME);
    X509Certificate requestSignerCertificate = (X509Certificate)x509certificateFactory.generateCertificate(requestSignerCertificateAsInputStream);
    Mockito.when(requestSignerCertificateService.getRequestSignerCertificate(Mockito.anyString()))
           .thenReturn(requestSignerCertificate);
    ResponseEntity<byte[]> responseEntity = controller.downloadRequestSignerCertificate(Mockito.anyString());

    HttpStatus statusCode = responseEntity.getStatusCode();
    Assertions.assertEquals(HttpStatus.OK, statusCode);
    HttpHeaders headers = responseEntity.getHeaders();
    ContentDisposition contentDisposition = headers.getContentDisposition();
    Assertions.assertEquals("attachment", contentDisposition.getType());
    Assertions.assertEquals(requestSignerCertificate.getSubjectDN().toString() + ".cer",
                            contentDisposition.getFilename());
    Assertions.assertEquals(MediaType.APPLICATION_OCTET_STREAM, headers.getContentType());
    byte[] body = responseEntity.getBody();
    Assertions.assertFalse(ArrayUtil.isNullOrEmpty(body));
  }
}

/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
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
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.web.servlet.mvc.support.RedirectAttributesModelMap;

import de.governikus.eumw.poseidas.cardbase.ArrayUtil;
import de.governikus.eumw.poseidas.server.exception.RequestSignerDownloadException;
import de.governikus.eumw.poseidas.server.idprovider.config.CvcTlsCheck;
import de.governikus.eumw.poseidas.server.pki.PermissionDataHandlingMBean;
import de.governikus.eumw.poseidas.server.pki.RequestSignerCertificateService;
import de.governikus.eumw.poseidas.server.pki.TerminalPermissionAO;
import de.governikus.eumw.poseidas.server.pki.model.CVCRequestModel;
import de.governikus.eumw.poseidas.service.MetadataService;


class CVCControllerTest
{

  CVCController controller;

  PermissionDataHandlingMBean data;

  MetadataService metadataService;

  RequestSignerCertificateService requestSignerCertificateService;

  CvcTlsCheck cvcTlsCheck;

  TerminalPermissionAO facade;

  @BeforeEach
  public void setUp()
  {
    Security.addProvider(new BouncyCastleProvider());
    Path resourceDirectory = Paths.get("src", "test", "resources");
    System.setProperty("spring.config.additional-location", resourceDirectory.toFile().getAbsolutePath());
    data = Mockito.mock(PermissionDataHandlingMBean.class);
    metadataService = Mockito.mock(MetadataService.class);
    requestSignerCertificateService = Mockito.mock(RequestSignerCertificateService.class);
    cvcTlsCheck = Mockito.mock(CvcTlsCheck.class);
    Mockito.when(cvcTlsCheck.checkCvcProvider(Mockito.anyString())).thenReturn(new CvcTlsCheck.CvcCheckResults());
    facade = Mockito.mock(TerminalPermissionAO.class);
    Mockito.when(facade.getTerminalPermission(Mockito.anyString())).thenReturn(null);
    controller = new CVCController(data, requestSignerCertificateService, cvcTlsCheck, facade);
  }

  @AfterAll
  public static void afterAll()
  {
    System.clearProperty("spring.config.additional-location");
  }

  @Test
  void testGenerateRSCSuccess()
  {
    String entityID = "testProvider";
    Mockito.when(requestSignerCertificateService.generateNewPendingRequestSignerCertificate(Mockito.anyString(),
                                                                                            Mockito.anyString(),
                                                                                            Mockito.anyInt()))
           .thenReturn(true);
    RedirectAttributes redirectAttributes = new RedirectAttributesModelMap();
    CVCRequestModel cvcRequestModel = new CVCRequestModel();
    cvcRequestModel.setRscChr("test");
    controller.generateRSC(entityID, redirectAttributes, cvcRequestModel);
    Assertions.assertTrue(redirectAttributes.getFlashAttributes().containsKey("success"));
    Assertions.assertTrue(redirectAttributes.getFlashAttributes().containsKey("resultMessage"));
    Assertions.assertEquals("Request signer certificate successfully created",
                            redirectAttributes.getFlashAttributes().get("resultMessage"));
  }

  @Test
  void testGenerateRSCFalse() throws Exception
  {
    String entityID = "testProvider";
    Mockito.when(requestSignerCertificateService.generateNewPendingRequestSignerCertificate(Mockito.anyString(),
                                                                                            Mockito.anyString(),
                                                                                            Mockito.anyInt()))
           .thenReturn(false);
    RedirectAttributes redirectAttributes = new RedirectAttributesModelMap();
    controller.generateRSC(entityID, redirectAttributes, new CVCRequestModel());
    Assertions.assertTrue(redirectAttributes.getFlashAttributes().containsKey("error"));
    Assertions.assertTrue(redirectAttributes.getFlashAttributes().containsKey("resultMessage"));
    Assertions.assertEquals("Creation of request signer certificate failed",
                            redirectAttributes.getFlashAttributes().get("resultMessage"));
  }

  @Test
  void testRequestDownloadExceptionIsThrownWhenByteArrayIsEmpty()
  {
    Mockito.when(requestSignerCertificateService.getRequestSignerCertificate(Mockito.anyString())).thenReturn(null);
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

/*
 * Copyright (c) 2021 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.pki.model;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Base64;
import java.util.Date;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import de.governikus.eumw.poseidas.server.idprovider.config.CvcTlsCheck;
import de.governikus.eumw.poseidas.server.pki.PermissionDataHandlingMBean;
import de.governikus.eumw.poseidas.server.pki.RequestSignerCertificateService;
import de.governikus.eumw.poseidas.server.pki.TerminalPermission;
import de.governikus.eumw.poseidas.server.pki.TerminalPermissionAO;


class ServiceProviderResultModelTest
{

  @Test
  void test() throws CertificateException, NoSuchProviderException
  {
    // Prepare test data
    Path resourceDirectory = Paths.get("src", "test", "resources");
    System.setProperty("spring.config.additional-location", resourceDirectory.toFile().getAbsolutePath());
    String providerName = "providerA";
    Date now = new Date();
    LocalDate nowLocalDate = now.toInstant().atZone(ZoneId.systemDefault()).toLocalDate();
    LocalDateTime nowLocalDateTime = now.toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime();
    Long version = 42L;
    byte[] data = "data".getBytes(StandardCharsets.UTF_8);
    String cvcDescription = "MIGQBgoEAH8ABwMBAwEBoRYMFEdvdmVybmlrdXMgVGVzdCBEVkNBohoTGGh0dHA6Ly93d3cuZ292ZXJuaWt1cy5kZaMKDAhCUFIgODQ0OKQYExZodHRwczovL2xvY2FsaG9zdDo4NDQ4pQIMAKckMSIEIF2fEYwONIdvuJzSQKQU1n+8ch2iQHhs5f0cLrQsx8ok";
    Security.addProvider(new BouncyCastleProvider());
    CertificateFactory cf = CertificateFactory.getInstance("X509", BouncyCastleProvider.PROVIDER_NAME);
    X509Certificate testCertificate = (X509Certificate)cf.generateCertificate(ServiceProviderResultModelTest.class.getResourceAsStream("/DE_TEST_CSCA_2018_12.cer"));

    CvcTlsCheck.CvcCheckResults result = new CvcTlsCheck.CvcCheckResults();
    result.setCvcPresent(true);
    result.setCvcTlsMatch(true);
    result.setCvcUrlMatch(true);
    result.setCvcValidity(true);

    TerminalPermission terminalPermission = new TerminalPermission();
    terminalPermission.setNotOnOrAfter(now);
    terminalPermission.setBlackListVersion(version);
    terminalPermission.setBlackListStoreDate(now);
    terminalPermission.setMasterList(data);
    terminalPermission.setMasterListStoreDate(now);
    terminalPermission.setDefectList(data);
    terminalPermission.setDefectListStoreDate(now);
    terminalPermission.setCvcDescription(Base64.getDecoder().decode(cvcDescription));

    TerminalPermissionAO facade = Mockito.mock(TerminalPermissionAO.class);
    Mockito.when(facade.getTerminalPermission(Mockito.anyString())).thenReturn(terminalPermission);

    PermissionDataHandlingMBean permissionDataHandling = Mockito.mock(PermissionDataHandlingMBean.class);
    Mockito.when(permissionDataHandling.pingPAService(Mockito.anyString())).thenReturn(true);
    Mockito.when(permissionDataHandling.pingRIService(Mockito.anyString())).thenReturn(true);

    RequestSignerCertificateService rscService = Mockito.mock(RequestSignerCertificateService.class);
    Mockito.when(rscService.getRequestSignerCertificate(Mockito.anyString(), Mockito.anyBoolean()))
           .thenReturn(testCertificate);

    // Create test object
    ServiceProviderResultModel model = new ServiceProviderResultModel(providerName, result, facade,
                                                                      permissionDataHandling, rscService);

    // Assert values
    Assertions.assertEquals(providerName, model.getServiceProviderName());
    Assertions.assertTrue(model.isCvcPresent());
    Assertions.assertEquals(nowLocalDate.minusDays(1), model.getCvcValidUntil());
    Assertions.assertEquals("https://localhost:8448", model.getCvcSubjectUrl());
    Assertions.assertTrue(model.isCvcTLSLinkStatus());
    Assertions.assertTrue(model.isBlackListPresent());
    Assertions.assertTrue(model.isBlackListDVCAAvailability());
    Assertions.assertEquals(nowLocalDateTime, model.getBlackListLastRetrieval());
    Assertions.assertTrue(model.isMasterListPresent());
    Assertions.assertTrue(model.isMasterListDVCAAvailability());
    Assertions.assertEquals(nowLocalDateTime, model.getMasterListLastRetrieval());
    Assertions.assertTrue(model.isDefectListPresent());
    Assertions.assertTrue(model.isDefectListDVCAAvailability());
    Assertions.assertEquals(nowLocalDateTime, model.getDefectListLastRetrieval());
    Assertions.assertTrue(model.isRscPendingPresent());
    Assertions.assertEquals(testCertificate.getNotAfter().toInstant().atZone(ZoneId.systemDefault()).toLocalDate(),
                            model.getRscCurrentValidUntil());
  }

}

/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.idprovider.config;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Optional;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mockito;
import org.mockserver.configuration.ConfigurationProperties;
import org.mockserver.integration.ClientAndServer;
import org.mockserver.junit.jupiter.MockServerExtension;

import de.governikus.eumw.config.EidasMiddlewareConfig;
import de.governikus.eumw.config.ServiceProviderType;
import de.governikus.eumw.poseidas.cardbase.Hex;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.CertificateDescription;
import de.governikus.eumw.poseidas.eidmodel.TerminalData;
import de.governikus.eumw.poseidas.server.idprovider.config.CvcTlsCheck.CvcCheckResults;
import de.governikus.eumw.poseidas.server.idprovider.config.CvcTlsCheck.CvcTlsCheckResult;
import de.governikus.eumw.poseidas.server.pki.TerminalPermission;
import de.governikus.eumw.poseidas.server.pki.TerminalPermissionAO;
import lombok.extern.slf4j.Slf4j;


@Slf4j
@ExtendWith(MockServerExtension.class)
class CvcTlsCheckTest
{

  private static final String CERTIFICATE_VALID = "certificate valid";

  public static final String DVCA_CONFIGURATION_NAME = "dvcaConfig";

  public static final String CLIENT_KEY_NAME = "clientKeyName";

  ConfigurationService configurationService;

  @Test
  void testNonHttpsServer() throws Exception
  {
    TerminalPermissionAO terminalPermission = mock(TerminalPermissionAO.class);
    configurationService = mock(ConfigurationService.class);
    Mockito.when(configurationService.getConfiguration())
           .thenReturn(Optional.of(ConfigurationTestHelper.createValidConfiguration()));
    CvcTlsCheck check = new CvcTlsCheck(terminalPermission, this.configurationService);
    CvcTlsCheckResult result = check.check().get();
    assertFalse(CERTIFICATE_VALID, result.isServerTlsValid());
  }

  @Test
  void testCheck() throws Exception
  {
    Path resourceDirectory = Paths.get("src", "test", "resources");

    TerminalPermissionAO terminalPermission = mock(TerminalPermissionAO.class);
    configurationService = mock(ConfigurationService.class);
    EidasMiddlewareConfig configuration = ConfigurationTestHelper.createValidConfiguration();
    configuration.setServerUrl("https://localhost:8450");
    configuration.getEidConfiguration()
                 .getServiceProvider()
                 .add(new ServiceProviderType("providerA", true, "provider_a", DVCA_CONFIGURATION_NAME,
                                              CLIENT_KEY_NAME));
    configuration.getEidConfiguration()
                 .getServiceProvider()
                 .add(new ServiceProviderType("providerB", true, "provider_b", DVCA_CONFIGURATION_NAME,
                                              CLIENT_KEY_NAME));
    configuration.getEidConfiguration()
                 .getServiceProvider()
                 .add(new ServiceProviderType("providerC", true, "provider_c", DVCA_CONFIGURATION_NAME,
                                              CLIENT_KEY_NAME));
    configuration.getEidConfiguration()
                 .getServiceProvider()
                 .add(new ServiceProviderType("providerD", true, "provider_d", DVCA_CONFIGURATION_NAME,
                                              CLIENT_KEY_NAME));
    configuration.getEidConfiguration()
                 .getServiceProvider()
                 .add(new ServiceProviderType("providerE", true, "provider_e", DVCA_CONFIGURATION_NAME,
                                              CLIENT_KEY_NAME));
    Mockito.when(configurationService.getConfiguration()).thenReturn(Optional.of(configuration));
    TerminalPermission tpA = mock(TerminalPermission.class);
    when(terminalPermission.getTerminalPermission("provider_a")).thenReturn(tpA);
    when(tpA.getFullCvc()).thenReturn(new TerminalData(Hex.parse("7f218201487f4e8201005f290100420e44454553544456314130303030317f494f060a04007f0007020202020386410457dcc1d8e2564196999e929499445cd41d4b98fd4c9cad27c3c8415cf12cddff9a6511410ce0844ad857d227408b509fec6687ab93bdcfc8d6e917baf6eda8d25f201044454553545445524d314130303030317f4c12060904007f00070301020253053c0ff3ffff5f25060106010000045f2406010601000005655e732d060904007f0007030103018020e2478043bdfe340e4029fceaf46c4001d57b33c3e65929fdedcdd32597f94236732d060904007f0007030103028020144969238b6ae406c90f22f1092bb83cc834020128d70b70fca6ca43bdc1d50f5f37403a9f4294b21c6ed37732853da4a538b1b55f68caf70b9b5f74b144869c1818b42f48d281af0963b5e49faa18c9935bf775d0b3e214fd71615d037efcd6af6522"),
                                                       Hex.parse("3081a6060a04007f00070301030101a1090c07736563756e6574a3140c126549442d5365727665722054657374626564a41a131868747470733a2f2f6c6f63616c686f73743a383435302f61a5130c114356205465726d73206f66205573616765a746314404205c6fcac6857d69b469b8e8e523b656338bdda1ac43dea739e0510c862901d06d042071b89f97689425ccad573f4754d74baafdbb95980d9135605eed4bf29781674c")));

    TerminalPermission tpB = mock(TerminalPermission.class);
    when(terminalPermission.getTerminalPermission("provider_b")).thenReturn(tpB);
    when(tpB.getFullCvc()).thenReturn(new TerminalData(Hex.parse("7f218201487f4e8201005f290100420e44454553544456314130303030317f494f060a04007f0007020202020386410457dcc1d8e2564196999e929499445cd41d4b98fd4c9cad27c3c8415cf12cddff9a6511410ce0844ad857d227408b509fec6687ab93bdcfc8d6e917baf6eda8d25f201044454553545445524d314130303030317f4c12060904007f00070301020253053c0ff3ffff5f25060106010000045f2406060000060103655e732d060904007f00070301030180203f8185d7c732cdcc2326a005a3d9188de01629cf0da3eacb380feaf54176c5b2732d060904007f0007030103028020144969238b6ae406c90f22f1092bb83cc834020128d70b70fca6ca43bdc1d50f5f37403a9f4294b21c6ed37732853da4a538b1b55f68caf70b9b5f74b144869c1818b42f48d281af0963b5e49faa18c9935bf775d0b3e214fd71615d037efcd6af6522"),
                                                       Hex.parse("3081a4060a04007f00070301030101a1090c07736563756e6574a3140c126549442d5365727665722054657374626564a418131668747470733A2F2F6C6F63616C686F73743A38343530a5130c114356205465726d73206f66205573616765a746314404205c6fcac6857d69b469b8e8e523b656338bdda1ac43dea739e0510c862901d06d0420f4bcf457aad98b6e53824d0f8afffe588472bb2f472115aee278717fa619a845")));

    TerminalPermission tpC = mock(TerminalPermission.class);
    when(terminalPermission.getTerminalPermission("provider_c")).thenReturn(tpC);
    when(tpC.getFullCvc()).thenReturn(new TerminalData(Hex.parse("7f218201487f4e8201005f290100420e44454553544456314130303030317f494f060a04007f0007020202020386410457dcc1d8e2564196999e929499445cd41d4b98fd4c9cad27c3c8415cf12cddff9a6511410ce0844ad857d227408b509fec6687ab93bdcfc8d6e917baf6eda8d25f201044454553545445524d314130303030317f4c12060904007f00070301020253053c0ff3ffff5f25060600010000045f2406060300060103655e732d060904007f0007030103018020885675b2ab976500e4b836d1d250011d1070c025bc8fd204157960f95b0b5569732d060904007f0007030103028020144969238b6ae406c90f22f1092bb83cc834020128d70b70fca6ca43bdc1d50f5f37403a9f4294b21c6ed37732853da4a538b1b55f68caf70b9b5f74b144869c1818b42f48d281af0963b5e49faa18c9935bf775d0b3e214fd71615d037efcd6af6522"),
                                                       Hex.parse("3081a6060a04007f00070301030101a1090c07736563756e6574a3140c126549442d5365727665722054657374626564a41a131868747470733a2f2f736f6d652e746573742e75726c2e6465a5130c114356205465726d73206f66205573616765a746314404205c6fcac6857d69b469b8e8e523b656338bdda1ac43dea739e0510c862901d06d042071b89f97689425ccad573f4754d74baafdbb95980d9135605eed4bf29781674c")));

    TerminalPermission tpD = mock(TerminalPermission.class);
    when(terminalPermission.getTerminalPermission("provider_d")).thenReturn(tpD);
    when(tpD.getFullCvc()).thenThrow(IllegalArgumentException.class);

    when(terminalPermission.getTerminalPermission("provider_e")).thenReturn(null);

    // no server running
    CvcTlsCheck check = new CvcTlsCheck(terminalPermission, configurationService);
    CvcTlsCheckResult result = check.check().get();
    assertFalse(CERTIFICATE_VALID, result.isServerTlsValid());

    // server running with expired cert
    ConfigurationProperties.x509CertificatePath(resourceDirectory + "/localhost_expired.pem");
    ConfigurationProperties.privateKeyPath(resourceDirectory + "/localhost_expired.pkcs8");
    ConfigurationProperties.certificateAuthorityCertificate(resourceDirectory + "/localhost_valid.pem");
    ConfigurationProperties.certificateAuthorityPrivateKey(resourceDirectory + "/localhost_valid.pkcs8");
    ClientAndServer clientAndServer = ClientAndServer.startClientAndServer(8450);
    result = check.check().get();
    clientAndServer.stop();
    assertFalse(CERTIFICATE_VALID, result.isServerTlsValid());


    // server running with not yet valid cert
    ConfigurationProperties.x509CertificatePath(resourceDirectory + "/localhost_notyetvalid.pem");
    ConfigurationProperties.privateKeyPath(resourceDirectory + "/localhost_notyetvalid.pkcs8");
    ConfigurationProperties.certificateAuthorityCertificate(resourceDirectory + "/localhost_valid.pem");
    ConfigurationProperties.certificateAuthorityPrivateKey(resourceDirectory + "/localhost_valid.pkcs8");
    clientAndServer = ClientAndServer.startClientAndServer(8450);
    result = check.check().get();
    clientAndServer.stop();
    assertFalse(CERTIFICATE_VALID, result.isServerTlsValid());

    // server running with valid cert
    ConfigurationProperties.x509CertificatePath(resourceDirectory + "/localhost_valid.pem");
    ConfigurationProperties.privateKeyPath(resourceDirectory + "/localhost_valid.pkcs8");
    ConfigurationProperties.certificateAuthorityCertificate(resourceDirectory + "/localhost_notyetvalid.pem");
    ConfigurationProperties.certificateAuthorityPrivateKey(resourceDirectory + "/localhost_notyetvalid.pkcs8");
    clientAndServer = ClientAndServer.startClientAndServer(8450);
    result = check.check().get();
    clientAndServer.stop();
    assertTrue("certificate invalid", result.isServerTlsValid());
    CvcCheckResults results = result.getProviderCvcChecks().get("providerA");
    assertTrue("CVC not present", results.isCvcPresent());
    assertFalse("CVC valid", results.isCvcValidity());
    assertTrue("server URLs match", results.isCvcUrlMatch());
    assertFalse("TLS cert in CVC", results.isCvcTlsMatch());
    results = result.getProviderCvcChecks().get("providerB");
    assertTrue("CVC not present", results.isCvcPresent());
    assertTrue("CVC invalid", results.isCvcValidity());
    assertTrue("server URLs do not match", results.isCvcUrlMatch());
    assertTrue("TLS cert not in CVC", results.isCvcTlsMatch());
    results = result.getProviderCvcChecks().get("providerC");
    assertTrue("CVC not present", results.isCvcPresent());
    assertFalse("CVC valid", results.isCvcValidity());
    results = result.getProviderCvcChecks().get("providerD");
    assertFalse("CVC present", results.isCvcPresent());
    assertFalse("CVC valid", results.isCvcValidity());
    assertFalse("server URLs match", results.isCvcUrlMatch());
    assertFalse("TLS cert in CVC", results.isCvcTlsMatch());
    results = result.getProviderCvcChecks().get("providerE");
    assertFalse("CVC present", results.isCvcPresent());
    assertFalse("CVC valid", results.isCvcValidity());
    assertFalse("server URLs match", results.isCvcUrlMatch());
    assertFalse("TLS cert in CVC", results.isCvcTlsMatch());
  }

  @Test
  void testCheckForOneServiceProvider() throws Exception
  {
    Path resourceDirectory = Paths.get("src", "test", "resources");

    TerminalPermissionAO terminalPermission = mock(TerminalPermissionAO.class);
    TerminalPermission tpB = mock(TerminalPermission.class);
    configurationService = mock(ConfigurationService.class);
    EidasMiddlewareConfig configuration = ConfigurationTestHelper.createValidConfiguration();
    configuration.setServerUrl("https://localhost:8450");
    configuration.getEidConfiguration()
                 .getServiceProvider()
                 .add(new ServiceProviderType("providerB", true, "provider_b", DVCA_CONFIGURATION_NAME,
                                              CLIENT_KEY_NAME));
    Mockito.when(configurationService.getConfiguration()).thenReturn(Optional.of(configuration));
    when(terminalPermission.getTerminalPermission("provider_b")).thenReturn(tpB);
    when(tpB.getFullCvc()).thenReturn(new TerminalData(Hex.parse("7f218201487f4e8201005f290100420e44454553544456314130303030317f494f060a04007f0007020202020386410457dcc1d8e2564196999e929499445cd41d4b98fd4c9cad27c3c8415cf12cddff9a6511410ce0844ad857d227408b509fec6687ab93bdcfc8d6e917baf6eda8d25f201044454553545445524d314130303030317f4c12060904007f00070301020253053c0ff3ffff5f25060106010000045f2406060000060103655e732d060904007f00070301030180203f8185d7c732cdcc2326a005a3d9188de01629cf0da3eacb380feaf54176c5b2732d060904007f0007030103028020144969238b6ae406c90f22f1092bb83cc834020128d70b70fca6ca43bdc1d50f5f37403a9f4294b21c6ed37732853da4a538b1b55f68caf70b9b5f74b144869c1818b42f48d281af0963b5e49faa18c9935bf775d0b3e214fd71615d037efcd6af6522"),
                                                       Hex.parse("3081a4060a04007f00070301030101a1090c07736563756e6574a3140c126549442d5365727665722054657374626564a418131668747470733A2F2F6C6F63616C686F73743A38343530a5130c114356205465726d73206f66205573616765a746314404205c6fcac6857d69b469b8e8e523b656338bdda1ac43dea739e0510c862901d06d0420f4bcf457aad98b6e53824d0f8afffe588472bb2f472115aee278717fa619a845")));
    ConfigurationProperties.x509CertificatePath(resourceDirectory + "/localhost_valid.pem");
    ConfigurationProperties.privateKeyPath(resourceDirectory + "/localhost_valid.pkcs8");
    ConfigurationProperties.certificateAuthorityCertificate(resourceDirectory + "/localhost_notyetvalid.pem");
    ConfigurationProperties.certificateAuthorityPrivateKey(resourceDirectory + "/localhost_notyetvalid.pkcs8");
    ClientAndServer clientAndServer = ClientAndServer.startClientAndServer(8450);
    CvcTlsCheck check = new CvcTlsCheck(terminalPermission, configurationService);
    CvcCheckResults results = check.checkCvcProvider("providerB");
    clientAndServer.stop();
    assertTrue("CVC not present", results.isCvcPresent());
    assertTrue("CVC invalid", results.isCvcValidity());
    assertTrue("server URLs do not match", results.isCvcUrlMatch());
    assertTrue("TLS cert not in CVC", results.isCvcTlsMatch());
  }

  @ParameterizedTest
  @ValueSource(strings = {"https://example.com/eumw", "https://example.com/eumw/", "https://example.com:/eumw/",
                          "https://example.com:443/eumw"})

  void testStartsWith(String subjcetUrl)
  {
    TerminalData terminalData = mock(TerminalData.class);
    CertificateDescription certificateDescription = mock(CertificateDescription.class);
    Mockito.when(terminalData.getCVCDescription()).thenReturn(certificateDescription);
    Mockito.when(certificateDescription.getSubjectUrl()).thenReturn(subjcetUrl);

    Assertions.assertTrue(CvcTlsCheck.testCvcUrlMatch(terminalData, "https://example.com/eumw"));
  }
}

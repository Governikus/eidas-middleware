package de.governikus.eumw.poseidas.server.pki;

import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import de.governikus.eumw.poseidas.server.pki.caserviceaccess.PassiveAuthService;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import com.google.common.io.ByteStreams;

import de.governikus.eumw.config.DvcaConfigurationType;
import de.governikus.eumw.config.EidasMiddlewareConfig;
import de.governikus.eumw.config.ServiceProviderType;
import de.governikus.eumw.poseidas.eidserver.model.signeddata.MasterList;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationService;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationTestHelper;
import de.governikus.eumw.utils.key.SecurityProvider;



@ExtendWith(MockitoExtension.class)
class MasterAndDefectListHandlerTest
{

  @Mock
  private TerminalPermission terminalPermission;

  @Mock
  private ServiceProviderType serviceProvider;

  @Mock
  private TerminalPermissionAO terminalPermissionAO;

  @Mock
  private PassiveAuthService passiveAuthService;

  @Mock
  private ConfigurationService configurationService;

  @BeforeEach
  void setUp() throws Exception
  {
    Mockito.when(terminalPermissionAO.getTerminalPermission("CVCRefID")).thenReturn(terminalPermission);
    Mockito.when(passiveAuthService.getMasterList())
           .thenReturn(getResourceAsByteArray("/masterlist/MASTERLIST.bin"));
    EidasMiddlewareConfig configuration = ConfigurationTestHelper.createValidConfiguration();
    DvcaConfigurationType dvcaConfigurationType = configuration.getEidConfiguration().getDvcaConfiguration().get(0);
    dvcaConfigurationType.setName("dvcaConfName");
    dvcaConfigurationType.setPassiveAuthServiceUrl("https://dvca-r1.governikus-eid.de:8444/gov_dvca/pa-service");
    Mockito.when(configurationService.getDvcaConfiguration(serviceProvider)).thenReturn(dvcaConfigurationType);
    Mockito.when(serviceProvider.getDvcaConfigurationName()).thenReturn("dvcaConfName");
    Mockito.when(serviceProvider.getCVCRefID()).thenReturn("CVCRefID");
  }

  @Test
  void testGetMasterListWithMasterListAsTrustAnchor() throws Exception
  {
    Mockito.when(terminalPermission.getMasterList())
           .thenReturn(getResourceAsByteArray("/masterlist/OLD_MASTERLIST.bin"));

    MasterAndDefectListHandler masterAndDefectListHandler = new MasterAndDefectListHandler(serviceProvider,
                                                                                           terminalPermissionAO, null,
                                                                                           configurationService);

    byte[] masterListByteArray = masterAndDefectListHandler.getMasterList(passiveAuthService);
    MasterList masterList = new MasterList(masterListByteArray);
    Assertions.assertEquals(11, masterList.getCertificates().size());
  }

  @Test
  void testGetMasterListWithTrustAnchorFromConfig() throws Exception
  {
    Mockito.when(terminalPermission.getMasterList()).thenReturn(null);
    X509Certificate rootCert = (X509Certificate)CertificateFactory.getInstance("X509",
                                                                               SecurityProvider.BOUNCY_CASTLE_PROVIDER)
                                                                  .generateCertificate(MasterAndDefectListHandlerTest.class.getResourceAsStream("/DE_TEST_CSCA_2018_12.cer"));
    Mockito.when(configurationService.getCertificate(Mockito.anyString())).thenReturn(rootCert);

    MasterAndDefectListHandler masterAndDefectListHandler = new MasterAndDefectListHandler(serviceProvider,
                                                                                           terminalPermissionAO, null,
                                                                                           configurationService);

    byte[] masterListByteArray = masterAndDefectListHandler.getMasterList(passiveAuthService);
    MasterList masterList = new MasterList(masterListByteArray);
    Assertions.assertEquals(11, masterList.getCertificates().size());
  }


  @Test
  void testGetMasterListReturnsMasterWithWrongMasterListFromTerminalPermission()
    throws Exception
  {
    Mockito.when(terminalPermission.getMasterList())
           .thenReturn(getResourceAsByteArray("/masterlist/wrongMasterList.bin"));
    X509Certificate rootCert = (X509Certificate)CertificateFactory.getInstance("X509",
                                                                               SecurityProvider.BOUNCY_CASTLE_PROVIDER)
                                                                  .generateCertificate(MasterAndDefectListHandlerTest.class.getResourceAsStream("/DE_TEST_CSCA_2018_12.cer"));
    Mockito.when(configurationService.getCertificate(Mockito.anyString())).thenReturn(rootCert);

    MasterAndDefectListHandler masterAndDefectListHandler = new MasterAndDefectListHandler(serviceProvider,
                                                                                           terminalPermissionAO, null,
                                                                                           configurationService);

    byte[] masterListByteArray = masterAndDefectListHandler.getMasterList(passiveAuthService);
    MasterList newMasterList = new MasterList(masterListByteArray);
    Assertions.assertEquals(11, newMasterList.getCertificates().size());
  }

  private byte[] getResourceAsByteArray(String path) throws Exception
  {
    try (InputStream resourceAsStream = MasterAndDefectListHandlerTest.class.getResourceAsStream(path))
    {
      return ByteStreams.toByteArray(resourceAsStream);
    }
  }
}

package de.governikus.eumw.poseidas.server.pki;

import java.io.InputStream;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import com.google.common.io.ByteStreams;

import de.governikus.eumw.poseidas.config.schema.PkiServiceType;
import de.governikus.eumw.poseidas.eidserver.model.signeddata.MasterList;
import de.governikus.eumw.poseidas.server.idprovider.config.EPAConnectorConfigurationDto;
import de.governikus.eumw.poseidas.server.idprovider.config.PkiConnectorConfigurationDto;
import de.governikus.eumw.poseidas.server.pki.caserviceaccess.PassiveAuthServiceWrapper;



@ExtendWith(MockitoExtension.class)
class MasterAndDefectListHandlerTest
{
  @Mock
  private TerminalPermission terminalPermission;

  @Mock
  private EPAConnectorConfigurationDto epaConnectorConfigurationDto;

  @Mock
  private TerminalPermissionAO terminalPermissionAO;

  @Mock
  private PkiConnectorConfigurationDto pkiConnectorConfigurationDto;

  @Mock
  private PassiveAuthServiceWrapper passiveAuthServiceWrapper;

  @BeforeEach
  void setUp() throws Exception
  {
    Security.addProvider(new BouncyCastleProvider());
    Mockito.when(epaConnectorConfigurationDto.getPkiConnectorConfiguration()).thenReturn(pkiConnectorConfigurationDto);
    Mockito.when(epaConnectorConfigurationDto.getCVCRefID()).thenReturn("CVCRefID");
    Mockito.when(terminalPermissionAO.getTerminalPermission("CVCRefID")).thenReturn(terminalPermission);
    Mockito.when(passiveAuthServiceWrapper.getMasterList())
           .thenReturn(getResourceAsByteArray("/masterlist/MASTERLIST.bin"));
  }

  @AfterEach
  void tearDown()
  {
    Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
  }

  @Test
  void testGetMasterListWithMasterListAsTrustAnchor() throws Exception
  {
    Mockito.when(terminalPermission.getMasterList())
           .thenReturn(getResourceAsByteArray("/masterlist/OLD_MASTERLIST.bin"));
    PkiServiceType pkiServiceType = Mockito.mock(PkiServiceType.class);
    Mockito.when(pkiConnectorConfigurationDto.getPassiveAuthService()).thenReturn(pkiServiceType);
    Mockito.when(pkiServiceType.getUrl()).thenReturn("https://dvca-r1.governikus-eid.de:8444/gov_dvca/pa-service");

    MasterAndDefectListHandler masterAndDefectListHandler = new MasterAndDefectListHandler(epaConnectorConfigurationDto,
                                                                                           terminalPermissionAO, null);

    byte[] masterListByteArray = masterAndDefectListHandler.getMasterList(passiveAuthServiceWrapper);
    MasterList masterList = new MasterList(masterListByteArray);
    Assertions.assertEquals(11, masterList.getCertificates().size());
  }

  @Test
  void testGetMasterListWithTrustAnchorFromConfig() throws Exception
  {
    Mockito.when(terminalPermission.getMasterList()).thenReturn(null);
    X509Certificate rootCert = (X509Certificate)CertificateFactory.getInstance("X509",
                                                                               BouncyCastleProvider.PROVIDER_NAME)
                                                                  .generateCertificate(MasterAndDefectListHandlerTest.class.getResourceAsStream("/DE_TEST_CSCA_2018_12.cer"));
    Mockito.when(pkiConnectorConfigurationDto.getMasterListTrustAnchor()).thenReturn(rootCert);
    PkiServiceType pkiServiceType = Mockito.mock(PkiServiceType.class);
    Mockito.when(pkiConnectorConfigurationDto.getPassiveAuthService()).thenReturn(pkiServiceType);
    Mockito.when(pkiServiceType.getUrl()).thenReturn("https://dvca-r1.governikus-eid.de:8444/gov_dvca/pa-service");

    MasterAndDefectListHandler masterAndDefectListHandler = new MasterAndDefectListHandler(epaConnectorConfigurationDto,
                                                                                           terminalPermissionAO, null);

    byte[] masterListByteArray = masterAndDefectListHandler.getMasterList(passiveAuthServiceWrapper);
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
                                                                               BouncyCastleProvider.PROVIDER_NAME)
                                                                  .generateCertificate(MasterAndDefectListHandlerTest.class.getResourceAsStream("/DE_TEST_CSCA_2018_12.cer"));
    Mockito.when(pkiConnectorConfigurationDto.getMasterListTrustAnchor()).thenReturn(rootCert);
    PkiServiceType pkiServiceType = Mockito.mock(PkiServiceType.class);
    Mockito.when(pkiConnectorConfigurationDto.getPassiveAuthService()).thenReturn(pkiServiceType);
    Mockito.when(pkiServiceType.getUrl()).thenReturn("https://dvca-r1.governikus-eid.de:8444/gov_dvca/pa-service");

    MasterAndDefectListHandler masterAndDefectListHandler = new MasterAndDefectListHandler(epaConnectorConfigurationDto,
                                                                                           terminalPermissionAO, null);

    byte[] masterListByteArray = masterAndDefectListHandler.getMasterList(passiveAuthServiceWrapper);
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

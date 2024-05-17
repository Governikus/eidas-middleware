package de.governikus.eumw.poseidas.server.pki;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Date;
import java.time.LocalDate;
import java.util.Base64;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.boot.test.util.TestPropertyValues;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;

import de.governikus.eumw.config.DvcaConfigurationType;
import de.governikus.eumw.config.ServiceProviderType;
import de.governikus.eumw.poseidas.cardbase.Hex;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationRepository;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationService;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationTestHelper;
import de.governikus.eumw.poseidas.server.pki.blocklist.BlockListService;
import de.governikus.eumw.poseidas.server.pki.caserviceaccess.DvcaServiceFactory;
import de.governikus.eumw.poseidas.server.pki.caserviceaccess.PKIServiceConnector;
import de.governikus.eumw.poseidas.server.pki.caserviceaccess.RestrictedIdService;
import de.governikus.eumw.poseidas.server.pki.entities.TerminalPermission;
import de.governikus.eumw.poseidas.server.pki.repositories.TerminalPermissionRepository;
import de.governikus.eumw.poseidas.server.timer.ApplicationTimer;


@ActiveProfiles("db") // Use application-db.properties
@SpringBootTest
@ContextConfiguration(initializers = PermissionDataHandlingTest.Initializer.class)
class PermissionDataHandlingTest
{

  // These CVCs have matching sector Ids, but the signatures are broken
  private static final String CVC_SP_1 = "7f218201487f4e8201005f290100420e44454553544456314130303030317f494f060a04007f0007020202020386410457dcc1d8e2564196999e929499445cd41d4b98fd4c9cad27c3c8415cf12cddff9a6511410ce0844ad857d227408b509fec6687ab93bdcfc8d6e917baf6eda8d25f201044454553545445524d314130303030317f4c12060904007f00070301020253053c0ff3ffff5f25060106010000045f2406010601000005655e732d060904007f0007030103018020e2478043bdfe340e4029fceaf46c4001d57b33c3e65929fdedcdd32597f94236732d060904007f0007030103028020c2bb2e8112a7ddbbdf731a7e3fb05199223d05b5919831a152a0c196226de2b45f37403a9f4294b21c6ed37732853da4a538b1b55f68caf70b9b5f74b144869c1818b42f48d281af0963b5e49faa18c9935bf775d0b3e214fd71615d037efcd6af6522";

  private static final String CVC_SP_2 = "7f218201487f4e8201005f290100420e44454553544456314130303030317f494f060a04007f0007020202020386410457dcc1d8e2564196999e929499445cd41d4b98fd4c9cad27c3c8415cf12cddff9a6511410ce0844ad857d227408b509fec6687ab93bdcfc8d6e917baf6eda8d25f201044454553545445524d314130303030317f4c12060904007f00070301020253053c0ff3ffff5f25060106010000045f2406010601000005655e732d060904007f0007030103018020e2478043bdfe340e4029fceaf46c4001d57b33c3e65929fdedcdd32597f94236732d060904007f0007030103028020c6bb2e8112a7ddbbdf731a7e3fb05199223d05b5919831a152a0c196226de2b45f37403a9f4294b21c6ed37732853da4a538b1b55f68caf70b9b5f74b144869c1818b42f48d281af0963b5e49faa18c9935bf775d0b3e214fd71615d037efcd6af6522";

  private static final String SECTOR_ID_B64 = "wrsugRKn3bvfcxp+P7BRmSI9BbWRmDGhUqDBliJt4rQ=";

  private static final String SECTOR_ID2_B64 = "xrsugRKn3bvfcxp+P7BRmSI9BbWRmDGhUqDBliJt4rQ=";

  private static final long BL_VERSION_COMPLETE = 1648652426392L;

  private static final long BL_VERSION_DELTA = 1648652426474L;

  private static final LocalDate LAST_BL_UPDATE_DATE = LocalDate.of(2004, 5, 8);

  private static final String SECOND_SP_CVC_REF_ID = ConfigurationTestHelper.CVC_REF_ID + "Second";

  @TempDir
  private static File tempDir;

  // Mock ApplicationTimer so no Timer will be executed
  @MockBean
  ApplicationTimer applicationTimer;

  @Autowired
  PermissionDataHandling permissionDataHandling;

  @Autowired
  ConfigurationService configurationService;

  @SpyBean
  BlockListService blockListService;

  @Autowired
  TerminalPermissionRepository terminalPermissionRepository;

  @Autowired
  ConfigurationRepository configurationRepository;

  // SpyBean so calls to the DVCA can be mocked
  @SpyBean
  DvcaServiceFactory dvcaServiceFactory;

  @Mock
  RestrictedIdService restrictedIdService;

  @Mock
  PKIServiceConnector pkiServiceConnector;


  @BeforeEach
  void setUp()
  {
    configurationRepository.deleteAll();
    terminalPermissionRepository.deleteAll();
  }

  @AfterEach
  void tearDown()
  {
    configurationRepository.deleteAll();
    terminalPermissionRepository.deleteAll();
  }

  @Test
  void testBlockListWithTwoSectorIdsFullApplication() throws Exception
  {
    saveConfiguration();
    // SP1
    saveTerminal(ConfigurationTestHelper.CVC_REF_ID, SECTOR_ID_B64, CVC_SP_1);
    // SP2
    saveTerminal(SECOND_SP_CVC_REF_ID, SECTOR_ID2_B64, CVC_SP_2);

    processCompleteBlockList();

    TerminalPermission terminalPermission1AfterBlRenewal = assertTerminalPermission(ConfigurationTestHelper.CVC_REF_ID,
                                                                                    BL_VERSION_COMPLETE);
    TerminalPermission terminalPermission2AfterBlRenewal = assertTerminalPermission(SECOND_SP_CVC_REF_ID,
                                                                                    BL_VERSION_COMPLETE);

    Assertions.assertTrue(Files.exists(Path.of(tempDir.getPath(),
                                               ConfigurationTestHelper.CVC_REF_ID + ".version-"
                                                                  + BL_VERSION_COMPLETE)));
    Assertions.assertTrue(Files.exists(Path.of(tempDir.getPath(),
                                               SECOND_SP_CVC_REF_ID + ".version-" + BL_VERSION_COMPLETE)));
    Assertions.assertEquals(30, blockListService.count(terminalPermission1AfterBlRenewal.getSectorID()));
    Assertions.assertEquals(30, blockListService.count(terminalPermission2AfterBlRenewal.getSectorID()));
    Assertions.assertTrue(blockListService.isOnBlockList(terminalPermission1AfterBlRenewal.getSectorID(),
                                                         Base64.getDecoder()
                                                               .decode("HYWtKfHlS/BXWFT9ka18skgJkzFX0GzvU/uMhxjMKwA=")));
    Assertions.assertTrue(blockListService.isOnBlockList(terminalPermission2AfterBlRenewal.getSectorID(),
                                                         Base64.getDecoder()
                                                               .decode("9SiiGOPZvVhl4lpycXLVApzlXq1dHRZklJ96Ufl6fFc=")));
    Assertions.assertFalse(blockListService.isOnBlockList(terminalPermission1AfterBlRenewal.getSectorID(),
                                                          Base64.getDecoder()
                                                                .decode("60hdZU5/6geFS6yvMlJD4iptJWFQEnoVv8kCO3DGI/k=")));
    Assertions.assertFalse(blockListService.isOnBlockList(terminalPermission2AfterBlRenewal.getSectorID(),
                                                          Base64.getDecoder()
                                                                .decode("60hdZU5/6geFS6yvMlJD4iptJWFQEnoVv8kCO3DGI/k=")));
    Mockito.verify(restrictedIdService).getBlacklistResult(Mockito.isNull(), Mockito.any());
    Mockito.verify(restrictedIdService).getSectorPublicKey(Base64.getDecoder().decode(SECTOR_ID_B64));
    Mockito.verify(restrictedIdService).getSectorPublicKey(Base64.getDecoder().decode(SECTOR_ID2_B64));
  }

  @Test
  void testDeltaBlForAllSP() throws Exception
  {
    saveConfiguration();
    // SP1
    saveTerminal(ConfigurationTestHelper.CVC_REF_ID, SECTOR_ID_B64, CVC_SP_1);
    // SP2
    saveTerminal(SECOND_SP_CVC_REF_ID, SECTOR_ID2_B64, CVC_SP_2);

    // First insert complete BL
    processCompleteBlockList();

    // Mock RIService
    Mockito.doReturn(restrictedIdService)
           .when(dvcaServiceFactory)
           .createRestrictedIdService(Mockito.any(), Mockito.any());
    // Mock BLResult from DVCA
    byte[] deltaAdded = PermissionDataHandlingTest.class.getResourceAsStream("/blockList/blacklist-delta+10x2")
                                                        .readAllBytes();
    byte[] deltaRemoved = PermissionDataHandlingTest.class.getResourceAsStream("/blockList/blacklist-delta-5x2")
                                                          .readAllBytes();
    Mockito.when(restrictedIdService.getBlacklistResult(Mockito.eq(BigInteger.valueOf(BL_VERSION_COMPLETE).toByteArray()), Mockito.any()))
           .thenReturn(new RestrictedIdService.BlackListResult(deltaAdded, deltaRemoved));


    // Renew Delta BL for all SP
    permissionDataHandling.renewBlackList(true, false);

    TerminalPermission terminalPermission1AfterBlRenewal = assertTerminalPermission(ConfigurationTestHelper.CVC_REF_ID,
                                                                                    BL_VERSION_DELTA);
    TerminalPermission terminalPermission2AfterBlRenewal = assertTerminalPermission(SECOND_SP_CVC_REF_ID,
                                                                                    BL_VERSION_DELTA);

    Assertions.assertTrue(Files.exists(Path.of(tempDir.getPath(),
                                               ConfigurationTestHelper.CVC_REF_ID + ".version-" + BL_VERSION_DELTA)));
    Assertions.assertTrue(Files.exists(Path.of(tempDir.getPath(),
                                               SECOND_SP_CVC_REF_ID + ".version-" + BL_VERSION_DELTA)));
    Assertions.assertEquals(35, blockListService.count(terminalPermission1AfterBlRenewal.getSectorID()));
    Assertions.assertEquals(35, blockListService.count(terminalPermission2AfterBlRenewal.getSectorID()));
    Assertions.assertTrue(blockListService.isOnBlockList(terminalPermission1AfterBlRenewal.getSectorID(),
                                                         Base64.getDecoder()
                                                               .decode("vP09IDiihg4bK7Zh3qBE/EaZi84+ZmZYZs+PVD78rV4=")));
    Assertions.assertTrue(blockListService.isOnBlockList(terminalPermission2AfterBlRenewal.getSectorID(),
                                                         Base64.getDecoder()
                                                               .decode("N6gtmN8CT7C+dhcld80AAUW1T1uFVbKNjhooonUlzo8=")));
    Assertions.assertFalse(blockListService.isOnBlockList(terminalPermission1AfterBlRenewal.getSectorID(),
                                                          Base64.getDecoder()
                                                                .decode("60hdZU5/6geFS6yvMlJD4iptJWFQEnoVv8kCO3DGI/k=")));
    Assertions.assertFalse(blockListService.isOnBlockList(terminalPermission2AfterBlRenewal.getSectorID(),
                                                          Base64.getDecoder()
                                                                .decode("60hdZU5/6geFS6yvMlJD4iptJWFQEnoVv8kCO3DGI/k=")));
    Mockito.verify(restrictedIdService).getBlacklistResult(Mockito.eq(BigInteger.valueOf(BL_VERSION_COMPLETE).toByteArray()), Mockito.any());
    Mockito.verify(blockListService, Mockito.times(2))
           .updateDeltaBlockList(Mockito.any(TerminalPermission.class),
                                 Mockito.eq(BL_VERSION_DELTA),
                                 Mockito.any(),
                                 Mockito.any());
  }

  private void saveConfiguration() throws IOException
  {
    String configString = new String(PermissionDataHandlingTest.class.getResourceAsStream("/blockList/eIDAS_Middleware_Config-for-BL-Tests.xml")
                                                                     .readAllBytes());
    configurationService.saveConfiguration(configString, false);
  }

  private void saveTerminal(String cvcRefId, String sectorId, String cvc)
  {
    TerminalPermission terminalPermission = new TerminalPermission(cvcRefId);
    terminalPermission.setSectorID(Base64.getDecoder().decode(sectorId));
    terminalPermission.setCvc(Hex.parse(cvc));
    terminalPermission.setBlackListVersion(0L);
    terminalPermission.setBlackListStoreDate(Date.valueOf(LAST_BL_UPDATE_DATE));
    terminalPermissionRepository.save(terminalPermission);
  }

  private void processCompleteBlockList() throws Exception
  {
    // Mock RIService
    Mockito.doReturn(restrictedIdService)
           .when(dvcaServiceFactory)
           .createRestrictedIdService(Mockito.any(), Mockito.any());
    // Mock BLResult from DVCA
    Mockito.when(restrictedIdService.getBlacklistResult(Mockito.isNull(), Mockito.any()))
           .thenReturn(new RestrictedIdService.BlackListResult("https://downloadBLHere.de"));

    // There should be only one dvca configuration
    DvcaConfigurationType dvcaConfiguration = configurationService.getConfiguration()
                                                                  .orElseThrow()
                                                                  .getEidConfiguration()
                                                                  .getDvcaConfiguration()
                                                                  .get(0);

    // Mock PKIService Connector
    Mockito.doReturn(pkiServiceConnector)
           .when(dvcaServiceFactory)
           .getPkiServiceConnector(Mockito.any(ServiceProviderType.class),
                                   Mockito.any(),
                                   Mockito.eq(dvcaConfiguration),
                                   Mockito.eq(180));

    // Mock BL download
    byte[] blockListBytes = PermissionDataHandlingTest.class.getResourceAsStream("/blockList/blacklist-complete30x2")
                                                            .readAllBytes();
    Mockito.when(pkiServiceConnector.getFile("https://downloadBLHere.de")).thenReturn(blockListBytes);

    // Renew BL for all SP
    permissionDataHandling.renewBlackList(false, false);
  }

  private TerminalPermission assertTerminalPermission(String cvcRefId, long blVersion)
  {
    TerminalPermission terminalPermission = terminalPermissionRepository.findById(cvcRefId)
                                                                                       .orElseThrow();
    Assertions.assertEquals(blVersion, terminalPermission.getBlackListVersion());
    Assertions.assertTrue(new java.util.Date().after(terminalPermission.getBlackListStoreDate()));
    return terminalPermission;
  }

  // Set the storage path top the tempDir path
  static class Initializer implements ApplicationContextInitializer<ConfigurableApplicationContext>
  {

    @Override
    public void initialize(ConfigurableApplicationContext applicationContext)
    {
      TestPropertyValues.of("blocklist.storage-folder = " + tempDir).applyTo(applicationContext);
    }
  }
}

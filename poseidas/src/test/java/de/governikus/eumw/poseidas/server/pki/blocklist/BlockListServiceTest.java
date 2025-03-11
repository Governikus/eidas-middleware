package de.governikus.eumw.poseidas.server.pki.blocklist;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Random;
import java.util.stream.IntStream;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.util.TestPropertyValues;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.test.context.ContextConfiguration;

import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationTestHelper;
import de.governikus.eumw.poseidas.server.pki.entities.TerminalPermission;
import de.governikus.eumw.poseidas.server.pki.repositories.TerminalPermissionRepository;


@SpringBootTest
@ContextConfiguration(initializers = BlockListServiceTest.Initializer.class, classes = {BlockListService.class,
                                                                                        BlockListServiceTest.MockedBeans.class})
class BlockListServiceTest
{

  private final static Random RANDOM = new Random();

  private final static byte[] SECTOR_ID = Base64.getDecoder().decode("q9WMX/cplbudRA4hPEIbRezuOnHJMTt2XxP0z2vsY+M=");

  private final static byte[] SPECIFIC_ID = Base64.getDecoder().decode("60hdZU5/6geFS6yvMlJD4iptJWFQEnoVv8kCO3DGI/k=");

  @TempDir
  private static File tempDir;

  @Autowired
  BlockListService blockListService;

  @Autowired
  TerminalPermissionRepository terminalPermissionRepository;

  private final static TerminalPermission terminalPermission = createTerminalPermission();

  @Test
  void testBlockListServiceFullUpdate() throws Exception
  {
    generateInitialBlockList(terminalPermission, SECTOR_ID);
    Assertions.assertFalse(blockListService.isOnBlockList(SECTOR_ID, SPECIFIC_ID));

    // Update BlockList with SpecificId on list
    blockListService.updateCompleteBlockList(terminalPermission,
                                             43,
                                             SECTOR_ID,
                                             generateRandomBlockListEntriesWithSpecificId());
    long count = blockListService.count(SECTOR_ID);
    Assertions.assertEquals(11, count);
    Assertions.assertTrue(blockListService.isOnBlockList(SECTOR_ID, SPECIFIC_ID));
    Assertions.assertEquals(43, terminalPermission.getBlackListVersion());
    Assertions.assertTrue(Files.exists(Path.of(tempDir.getPath(), ConfigurationTestHelper.CVC_REF_ID + ".version-43")));
    Mockito.verify(terminalPermissionRepository, Mockito.times(2)).save(terminalPermission);
  }

  @Test
  void testBlockListServiceDeltaUpdate() throws Exception
  {
    List<byte[]> blockListEntries = generateRandomBlockListEntries(10);
    generateInitialBlockList(terminalPermission, SECTOR_ID, blockListEntries);

    List<byte[]> entriesToAdd = generateRandomBlockListEntries(2);
    List<byte[]> entriesToRemove = blockListEntries.subList(0, 3);
    blockListService.updateDeltaBlockList(terminalPermission, 43, entriesToAdd, entriesToRemove, null);
    long count = blockListService.count(SECTOR_ID);
    Assertions.assertEquals(9, count);
    Assertions.assertTrue(Files.exists(Path.of(tempDir.getPath(), ConfigurationTestHelper.CVC_REF_ID + ".version-43")));
    Assertions.assertFalse(Files.exists(Path.of(tempDir.getPath(),
                                                ConfigurationTestHelper.CVC_REF_ID + ".version-42")));
  }

  @Test
  void testBlockListServiceRemoveBlockListForSectorId() throws Exception
  {
    generateInitialBlockList(terminalPermission, SECTOR_ID);
    blockListService.removeBlockList(terminalPermission);
    long count = blockListService.count(SECTOR_ID);
    Assertions.assertEquals(0, count);
    Assertions.assertFalse(Files.exists(Path.of(tempDir.getPath(),
                                                ConfigurationTestHelper.CVC_REF_ID + ".version-42")));
  }

  private static TerminalPermission createTerminalPermission()
  {
    TerminalPermission terminalPermission = new TerminalPermission();
    terminalPermission.setRefID(ConfigurationTestHelper.CVC_REF_ID);
    terminalPermission.setSectorID(SECTOR_ID);
    return terminalPermission;
  }

  private void generateInitialBlockList(TerminalPermission terminalPermission,
                                        byte[] sectorID,
                                        List<byte[]> blockListEntries)
    throws BlockListStorageException
  {
    blockListService.updateCompleteBlockList(terminalPermission, 42, sectorID, blockListEntries);
    long count = blockListService.count(sectorID);
    Assertions.assertEquals(10, count);
    Assertions.assertEquals(42, terminalPermission.getBlackListVersion());
    Assertions.assertTrue(Files.exists(Path.of(tempDir.getPath(), ConfigurationTestHelper.CVC_REF_ID + ".version-42")));
  }

  private void generateInitialBlockList(TerminalPermission terminalPermission, byte[] sectorID)
    throws BlockListStorageException
  {
    generateInitialBlockList(terminalPermission, sectorID, generateRandomBlockListEntries(10));
  }

  private List<byte[]> generateRandomBlockListEntriesWithSpecificId()
  {
    List<byte[]> blockListEntries = generateRandomBlockListEntries(10);
    blockListEntries.add(SPECIFIC_ID);
    return blockListEntries;
  }

  private List<byte[]> generateRandomBlockListEntries(int numberOfEntries)
  {
    List<byte[]> blockListEntries = new ArrayList<>();
    IntStream.range(0, numberOfEntries).mapToObj(i -> new byte[32]).forEach(entry -> {
      RANDOM.nextBytes(entry);
      blockListEntries.add(entry);
    });
    return blockListEntries;
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

  // Mocked Beans to use the mocks already in the BlockListService @PostConstruct method
  @TestConfiguration
  static class MockedBeans
  {

    @Bean
    @Primary
    public TerminalPermissionRepository mockedTerminalPermissionRepository()
    {
      TerminalPermissionRepository mockedTerminalPermission = Mockito.mock(TerminalPermissionRepository.class);
      Mockito.when(mockedTerminalPermission.findAll()).thenReturn(List.of(terminalPermission));
      return mockedTerminalPermission;
    }
  }
}

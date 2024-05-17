package de.governikus.eumw.poseidas.server.pki.blocklist;

import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Random;
import java.util.Set;
import java.util.stream.Stream;

import jakarta.annotation.PostConstruct;

import org.apache.commons.codec.binary.Base64;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.google.common.collect.HashMultimap;
import com.google.common.collect.Multimap;

import de.governikus.eumw.poseidas.server.pki.entities.TerminalPermission;
import de.governikus.eumw.poseidas.server.pki.repositories.TerminalPermissionRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;


/**
 * This service manages the storage, and handling of Block Lists
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class BlockListService
{

  private static final Random RANDOM = new Random();

  @Value("${blocklist.storage-folder:block-list-data}")
  private String storageFolderName;

  private final TerminalPermissionRepository terminalPermissionRepository;

  private final Multimap<String, String> blockListStorage = HashMultimap.create();

  private final Set<String> cvcRefIdsWithList = new HashSet<>();

  /**
   * Initial loading of the Block Lists from file storage into memory.
   */
  @PostConstruct
  synchronized void initialLoad()
  {
    File storageFolder = new File(storageFolderName);
    log.info("Folder for Block List files is: {}", storageFolder.getAbsolutePath());
    storageFolder.mkdirs();
    List<TerminalPermission> terminalPermissions = terminalPermissionRepository.findAll();

    for ( TerminalPermission tp : terminalPermissions )
    {
      try
      {
        long loadedEntries = loadBlockListFromStorage(tp);
        log.debug("Loaded {} Block List entries from storage for service provider with cvcRefId: {}",
                  loadedEntries,
                  tp.getRefID());
        cvcRefIdsWithList.add(tp.getRefID());
      }
      catch (BlockListStorageException e)
      {
        log.error("Could not load Block List file for service provider with cvcRefId {} with error message: {}",
                  tp.getRefID(),
                  e.getMessage());
        log.debug("Error when trying to load Block List file for service provider with cvcRefId: {}", tp.getRefID(), e);
        cvcRefIdsWithList.remove(tp.getRefID());
      }
    }
    log.debug("Finished loading Block List entries. Currently loaded entries: {}", blockListStorage.values().size());
  }

  /**
   * Get information if a given SP has successfully loaded a blocklist.
   *
   * @param cvcRefId CVCRefID of SP
   * @return <code>true</code> if blocklist available, <code>false</code> otherwise
   */
  public synchronized boolean hasBlockList(String cvcRefId)
  {
    return cvcRefIdsWithList.contains(cvcRefId);
  }

  /**
   * Counts the amount of stored entries for a sector id
   *
   * @param sectorID
   * @return count of stored entries
   */
  public long count(byte[] sectorID)
  {
    return blockListStorage.get(encodeSectorIdToBase64String(sectorID)).size();
  }

  /**
   * Checks if a specific id is on the Block List of a sector id
   *
   * @param sectorID the sector ID for this Block List
   * @param specificID the specific ID to check
   * @return true if the specificID is on the Block List for this sector id
   */
  public boolean isOnBlockList(byte[] sectorID, byte[] specificID)
  {
    return blockListStorage.containsEntry(encodeSectorIdToBase64String(sectorID),
                                          encodeSectorIdToBase64String(specificID));
  }

  /**
   * Stores a complete Block List in a file
   *
   * @param terminalPermission the terminal permission for which a Block List should be saved
   * @param newBlockListID the new id of the Block List
   * @param newSectorID the new sector id of the Block List
   * @param entries entries that shall be stored
   * @throws BlockListStorageException when the Block List for this terminal permission can not be saved in a file
   */
  public synchronized void updateCompleteBlockList(TerminalPermission terminalPermission,
                                                   Number newBlockListID,
                                                   byte[] newSectorID,
                                                   List<byte[]> entries)
    throws BlockListStorageException
  {
    List<String> entriesAsBase64List = entries.parallelStream().map(Base64::encodeBase64String).toList();
    updateBlockList(terminalPermission, newBlockListID, entriesAsBase64List, newSectorID);
  }

  /**
   * Stores a delta black list
   *
   * @param terminalPermission
   * @param blockListID the new id of the blocklist
   * @param entriesToAdd entries that shall be added
   * @param entriesToRemove entries that shall be removed
   * @throws BlockListStorageException
   */
  public synchronized void updateDeltaBlockList(TerminalPermission terminalPermission,
                                                Number blockListID,
                                                List<byte[]> entriesToAdd,
                                                List<byte[]> entriesToRemove

  ) throws BlockListStorageException
  {
    var newBlockList = new ArrayList<>(blockListStorage.get(encodeSectorIdToBase64String(terminalPermission.getSectorID())));

    List<String> entriesToRemoveAsBase64 = entriesToRemove.parallelStream().map(Base64::encodeBase64String).toList();
    List<String> entriesToAddAsBase64 = entriesToAdd.parallelStream().map(Base64::encodeBase64String).toList();
    newBlockList.removeAll(entriesToRemoveAsBase64);
    newBlockList.addAll(entriesToAddAsBase64);

    updateBlockList(terminalPermission, blockListID, newBlockList, terminalPermission.getSectorID());
  }

  /**
   * Removes a Block List from disk and in memory storage
   *
   * @param terminalPermission the terminal permission for which the Block List should be removed
   * @throws BlockListStorageException if the Block List file for this terminal permission could not be deleted
   */
  public synchronized void removeBlockList(TerminalPermission terminalPermission) throws BlockListStorageException
  {
    blockListStorage.removeAll(encodeSectorIdToBase64String(terminalPermission.getSectorID()));
    var blockListFile = buildPathToBlockListFile(terminalPermission.getRefID(),
                                                 terminalPermission.getBlackListVersion());
    try
    {
      Files.deleteIfExists(blockListFile);
    }
    catch (IOException e)
    {
      log.debug("Could not delete Block List file for sp with cvcRefId {}: {}",
                terminalPermission.getRefID(),
                blockListFile);
      throw new BlockListStorageException("Could not delete Block List file for sp %s: %s".formatted(terminalPermission.getRefID(),
                                                                                                     blockListFile),
                                          e);
    }
  }

  private void updateBlockList(TerminalPermission terminalPermission,
                               Number blockListID,
                               List<String> newBlockList,
                               byte[] newSectorID)
    throws BlockListStorageException
  {
    // Generate temporary working file
    Path tmpBlockListFile;
    do
    {
      tmpBlockListFile = buildPathToBlockListFile("tmp-" + terminalPermission.getRefID(),
                                                  RANDOM.nextInt(100_000) + 100_000);
    }
    while (Files.exists(tmpBlockListFile));

    // Write to temporary working file
    writeTemporaryFile(terminalPermission.getRefID(), newBlockList, tmpBlockListFile);

    // Check temporary working file
    validateWrittenFile(terminalPermission.getRefID(), tmpBlockListFile, newBlockList.size());

    // Exchange files
    var newBlockListFileName = buildPathToBlockListFile(terminalPermission.getRefID(), blockListID);
    try
    {
      Files.move(tmpBlockListFile, newBlockListFileName, StandardCopyOption.REPLACE_EXISTING);
    }
    catch (IOException e)
    {
      throw new BlockListStorageException("Could not delete current Block List file for renewal of sp with cvcRefId %s: %s".formatted(terminalPermission.getRefID(),
                                                                                                                                      newBlockListFileName),
                                          e);
    }

    // Finally update in memory storage
    blockListStorage.replaceValues(encodeSectorIdToBase64String(newSectorID), newBlockList);
    cvcRefIdsWithList.add(terminalPermission.getRefID());

    byte[] oldSectorID = terminalPermission.getSectorID();
    long oldBlockListVersion = terminalPermission.getBlackListVersion() == null ? 0
      : terminalPermission.getBlackListVersion();
    updateBlackListVersionAndStoreDate(terminalPermission, newSectorID, blockListID);

    if (!Arrays.equals(oldSectorID, newSectorID))
    {
      blockListStorage.removeAll(encodeSectorIdToBase64String(oldSectorID));
    }
    if (oldBlockListVersion != blockListID.longValue())
    {
      Path path = buildPathToBlockListFile(terminalPermission.getRefID(), oldBlockListVersion);
      try
      {
        Files.deleteIfExists(path);
      }
      catch (IOException e)
      {
        log.info("Could not delete old Block List file: {}", path);
      }
    }
  }

  private void validateWrittenFile(String cvcRefId, Path blockListFile, int expectedEntries)
    throws BlockListStorageException
  {
    try (Stream<String> stream = Files.lines(blockListFile, StandardCharsets.UTF_8))
    {
      long count = stream.count();
      if (count != expectedEntries)
      {
        throw new BlockListStorageException("Written Block List for sp with cvcRefId %s entries are incomplete.%nExpected entries: %s%nFound entries: %s".formatted(cvcRefId,
                                                                                                                                                                    expectedEntries,
                                                                                                                                                                    count));
      }
    }
    catch (IOException e)
    {
      throw new BlockListStorageException("Could not check temporary Block List to file for sp with cvcRefId %s: %s".formatted(cvcRefId,
                                                                                                                               blockListFile),
                                          e);
    }
  }

  private void writeTemporaryFile(String cvcRefId, List<String> entries, Path tmpBlockListFile)
    throws BlockListStorageException
  {
    try (
      BufferedWriter bufferedWriter = Files.newBufferedWriter(tmpBlockListFile,
                                                              StandardCharsets.UTF_8,
                                                              StandardOpenOption.CREATE);
      var fileWriter = new PrintWriter(bufferedWriter))
    {
      entries.parallelStream().forEach(fileWriter::println);
      fileWriter.flush();
    }
    catch (IOException e)
    {
      throw new BlockListStorageException("Could not write temporary Block List to file for sp with cvcRefId %s: %s".formatted(cvcRefId,
                                                                                                                               tmpBlockListFile),
                                          e);
    }
  }

  private long loadBlockListFromStorage(TerminalPermission terminalPermission) throws BlockListStorageException
  {
    var currentBlockListVersion = terminalPermission.getBlackListVersion();
    var blockListStoreDate = terminalPermission.getBlackListStoreDate();
    if (currentBlockListVersion == null || blockListStoreDate == null)
    {
      throw new BlockListStorageException("SP with CVCRefID" + terminalPermission.getRefID()
                                          + " has never received a blocklist");
    }

    File blockListFile = findBlockListFile(terminalPermission.getRefID(), currentBlockListVersion);
    return readBlockListFileIntoMemory(blockListFile, terminalPermission);
  }

  private long readBlockListFileIntoMemory(File blockListFile, TerminalPermission terminalPermission)
    throws BlockListStorageException
  {
    try (Stream<String> lines = Files.lines(blockListFile.toPath()))
    {
      var blockListEntries = lines.parallel().toList();
      String sectorID = encodeSectorIdToBase64String(terminalPermission.getSectorID());
      blockListStorage.replaceValues(sectorID, blockListEntries);
      return blockListStorage.get(sectorID).size();
    }
    catch (IOException e)
    {
      throw new BlockListStorageException("Could not read Block List file entries: %s".formatted(blockListFile.getAbsolutePath()),
                                          e);
    }
  }

  private File findBlockListFile(String cvcRefId, Long currentBlockListVersion) throws BlockListStorageException
  {

    File currentBlockListFile = buildPathToBlockListFile(cvcRefId, currentBlockListVersion).toFile();
    if (!currentBlockListFile.exists())
    {
      throw new BlockListStorageException("Could not find Block List file: %s".formatted(currentBlockListFile.getAbsoluteFile()));
    }
    if (!currentBlockListFile.isFile())
    {
      throw new BlockListStorageException("Found Block List file is a directory:  %s".formatted(currentBlockListFile.getAbsoluteFile()));
    }
    if (!currentBlockListFile.canRead())
    {
      throw new BlockListStorageException("Insufficient rights to read Block List file: %s".formatted(currentBlockListFile.getAbsoluteFile()));
    }
    return currentBlockListFile;
  }

  private Path buildPathToBlockListFile(String cvcRefId, Number blockListVersion)
  {
    return Path.of(storageFolderName, "%s.version-%s".formatted(cvcRefId, blockListVersion));
  }

  private void updateBlackListVersionAndStoreDate(TerminalPermission terminalPermission,
                                                  byte[] sectorID,
                                                  Number blackListId)
  {
    if (sectorID != null)
    {
      terminalPermission.setSectorID(sectorID);
    }
    terminalPermission.setBlackListStoreDate(new Date());
    if (blackListId != null)
    {
      terminalPermission.setBlackListVersion(blackListId.longValue());
    }
    terminalPermissionRepository.save(terminalPermission);
  }

  private static String encodeSectorIdToBase64String(byte[] sectorID)
  {
    return Base64.encodeBase64String(sectorID);
  }
}


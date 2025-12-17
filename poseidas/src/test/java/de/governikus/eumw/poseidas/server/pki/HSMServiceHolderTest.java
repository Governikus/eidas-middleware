package de.governikus.eumw.poseidas.server.pki;

import java.sql.Date;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import de.governikus.eumw.poseidas.cardserver.service.hsm.impl.HSMService;
import de.governikus.eumw.poseidas.gov2server.constants.admin.ManagementMessage;
import de.governikus.eumw.poseidas.server.pki.entities.ChangeKeyLock;

import lombok.SneakyThrows;


@ExtendWith(MockitoExtension.class)
class HSMServiceHolderTest
{

  public static final String HSM_TYPE = "PKCS11";

  @Mock
  HSMService hsmService;

  @Mock
  TerminalPermissionAO facade;

  HSMServiceHolder hsmServiceHolder;

  private final int deleteKeysOlderThenDays = 2;

  @BeforeEach
  @SneakyThrows
  void setUp()
  {
    Mockito.reset(hsmService, facade);
    hsmServiceHolder = getHsmServiceHolder(HSM_TYPE, deleteKeysOlderThenDays, true);
    hsmServiceHolder.setService(hsmService); // Inject mock service
  }

  private HSMServiceHolder getHsmServiceHolder(String hsmType, int deleteKeysOlderThenDays, boolean archiveOldKeys)
  {
    return new HsmServiceHolderTestWrapper(hsmType, deleteKeysOlderThenDays, archiveOldKeys, facade);
  }

  @Test
  void deleteOutdatedKeysWithNoHsm()
  {
    hsmServiceHolder = getHsmServiceHolder("nicht PKCS11", 2, true);
    HSMServiceHolder.KeyDeletionResult keyDeletionResult = Assertions.assertDoesNotThrow(() -> hsmServiceHolder.deleteOutdatedKeys());

    Assertions.assertTrue(keyDeletionResult.success());
    Assertions.assertEquals("HSM is not in use - no deletion of outdated keys necessary", keyDeletionResult.message());
  }

  @SneakyThrows
  @Test
  void deleteOutdatedKeysWithOnlyValidAliases()
  {
    Mockito.doReturn(true).when(hsmService).isAlive(Mockito.anyBoolean());
    hsmServiceHolder = getHsmServiceHolder(HSM_TYPE, deleteKeysOlderThenDays, true);
    hsmServiceHolder.setService(hsmService);


    Mockito.doReturn(List.of("good-1", "good-2")).when(hsmService).getAliases();
    mockKeyAlias("good-1", 1); // one day valid
    mockKeyAlias("good-2", 2); // two days valid

    HSMServiceHolder.KeyDeletionResult keyDeletionResult = Assertions.assertDoesNotThrow(() -> hsmServiceHolder.deleteOutdatedKeys());

    Assertions.assertTrue(keyDeletionResult.success(),
                          "Result is not as expected with message " + keyDeletionResult.message());
    Assertions.assertEquals("No keys present to delete", keyDeletionResult.message());

    Mockito.verify(hsmService, Mockito.times(1)).getExpirationDate("good-1");
    Mockito.verify(hsmService, Mockito.times(1)).getExpirationDate("good-2");

    Mockito.verify(hsmService, Mockito.never()).deleteKey(Mockito.anyString());
    Mockito.verify(hsmService, Mockito.never()).exportKey(Mockito.anyString());
    Mockito.verify(facade, Mockito.never()).archiveKey(Mockito.anyString(), Mockito.any());
  }

  @SneakyThrows
  @Test
  void deleteOutdatedKeysWithOnlyValidAliasesAndGenerationDate()
  {
    Mockito.doReturn(true).when(hsmService).isAlive(Mockito.anyBoolean());
    hsmServiceHolder = getHsmServiceHolder(HSM_TYPE, deleteKeysOlderThenDays, true);
    hsmServiceHolder.setService(hsmService);


    Mockito.doReturn(List.of("good-1", "good-2")).when(hsmService).getAliases();
    mockKeyAlias("good-1", 1); // one day valid
    Mockito.doThrow(new UnsupportedOperationException("")).when(hsmService).getExpirationDate("good-2");
    Mockito.doReturn(Date.from(Instant.now().plusSeconds(60).plus(2, ChronoUnit.DAYS)))
           .when(hsmService)
           .getGenerationDate("good-2");

    HSMServiceHolder.KeyDeletionResult keyDeletionResult = Assertions.assertDoesNotThrow(() -> hsmServiceHolder.deleteOutdatedKeys());

    Assertions.assertTrue(keyDeletionResult.success(),
                          "Result is not as expected with message " + keyDeletionResult.message());
    Assertions.assertEquals("No keys present to delete", keyDeletionResult.message());

    Mockito.verify(hsmService, Mockito.times(1)).getExpirationDate("good-1");
    Mockito.verify(hsmService, Mockito.times(1)).getExpirationDate("good-2");
    Mockito.verify(hsmService, Mockito.times(1)).getGenerationDate("good-2");

    Mockito.verify(hsmService, Mockito.never()).deleteKey(Mockito.anyString());
    Mockito.verify(hsmService, Mockito.never()).exportKey(Mockito.anyString());
    Mockito.verify(facade, Mockito.never()).archiveKey(Mockito.anyString(), Mockito.any());
  }

  @SneakyThrows
  @Test
  void deleteOutdatedKeysWithOneOld()
  {
    Mockito.doReturn(true).when(hsmService).isAlive(Mockito.anyBoolean());
    hsmServiceHolder = getHsmServiceHolder(HSM_TYPE, deleteKeysOlderThenDays, true);
    hsmServiceHolder.setService(hsmService);


    Mockito.doReturn(List.of("good-1", "good-2", "old-1", "old-2")).when(hsmService).getAliases();
    mockKeyAlias("good-1", 1); // one day valid
    mockKeyAlias("good-2", 2); // two days valid
    mockKeyAlias("old-1", -(deleteKeysOlderThenDays + 1)); // one day over limit
    mockKeyAlias("old-2", -(deleteKeysOlderThenDays - 1)); // one day before limit

    Mockito.doReturn(Mockito.mock(ChangeKeyLock.class))
           .when(facade)
           .obtainChangeKeyLock("old-1", ChangeKeyLock.TYPE_DELETE);


    HSMServiceHolder.KeyDeletionResult keyDeletionResult = Assertions.assertDoesNotThrow(() -> hsmServiceHolder.deleteOutdatedKeys());

    Assertions.assertTrue(keyDeletionResult.success(),
                          "Result is not as expected with message " + keyDeletionResult.message());
    Assertions.assertEquals("The following keys were deleted from the HSM: old-1", keyDeletionResult.message());

    Mockito.verify(hsmService, Mockito.times(1)).getExpirationDate("good-1");
    Mockito.verify(hsmService, Mockito.times(1)).getExpirationDate("good-2");
    Mockito.verify(hsmService, Mockito.times(1)).getExpirationDate("old-1");
    Mockito.verify(hsmService, Mockito.times(1)).getExpirationDate("old-2");

    Mockito.verify(facade, Mockito.never()).archiveKey(Mockito.eq("good-1"), Mockito.any());
    Mockito.verify(facade, Mockito.never()).archiveKey(Mockito.eq("good-2"), Mockito.any());
    Mockito.verify(facade, Mockito.times(1)).archiveKey(Mockito.eq("old-1"), Mockito.any());
    Mockito.verify(facade, Mockito.never()).archiveKey(Mockito.eq("old-2"), Mockito.any());

    Mockito.verify(hsmService, Mockito.never()).deleteKey("good-1");
    Mockito.verify(hsmService, Mockito.never()).deleteKey("good-2");
    Mockito.verify(hsmService, Mockito.times(1)).deleteKey("old-1");
    Mockito.verify(hsmService, Mockito.never()).deleteKey("old-2");

    Mockito.verify(hsmService, Mockito.never()).exportKey("good-1");
    Mockito.verify(hsmService, Mockito.never()).exportKey("good-2");
    Mockito.verify(hsmService, Mockito.times(1)).exportKey("old-1");
    Mockito.verify(hsmService, Mockito.never()).exportKey("old-2");
  }

  @SneakyThrows
  private void mockKeyAlias(String alias, int daysValidFromNow)
  {
    Mockito.doReturn(Date.from(Instant.now().plusSeconds(60).plus(daysValidFromNow, ChronoUnit.DAYS)))
           .when(hsmService)
           .getExpirationDate(alias);
  }

  @SneakyThrows
  @Test
  void deleteOutdatedKeysWithFailingArchive()
  {
    Mockito.doReturn(true).when(hsmService).isAlive(Mockito.anyBoolean());
    hsmServiceHolder = getHsmServiceHolder(HSM_TYPE, deleteKeysOlderThenDays, true);
    hsmServiceHolder.setService(hsmService);


    Mockito.doReturn(List.of("good-1", "good-2", "old-1")).when(hsmService).getAliases();
    mockKeyAlias("good-1", 1); // one day valid
    mockKeyAlias("good-2", 2); // zwo days valid
    mockKeyAlias("old-1", -(deleteKeysOlderThenDays + 1)); // one day over limit

    Mockito.doReturn(Mockito.mock(ChangeKeyLock.class))
           .when(facade)
           .obtainChangeKeyLock("old-1", ChangeKeyLock.TYPE_DELETE);
    Mockito.doThrow(new UnsupportedOperationException()).when(facade).archiveKey(Mockito.eq("old-1"), Mockito.any());

    HSMServiceHolder.KeyDeletionResult keyDeletionResult = Assertions.assertDoesNotThrow(() -> hsmServiceHolder.deleteOutdatedKeys());

    Assertions.assertTrue(keyDeletionResult.success(),
                          "Result is not as expected with message " + keyDeletionResult.message());
    Assertions.assertEquals("No keys present to delete", keyDeletionResult.message());

    Mockito.verify(hsmService, Mockito.times(1)).getExpirationDate("good-1");
    Mockito.verify(hsmService, Mockito.times(1)).getExpirationDate("good-2");
    Mockito.verify(hsmService, Mockito.times(1)).getExpirationDate("old-1");

    Mockito.verify(facade, Mockito.never()).archiveKey(Mockito.eq("good-1"), Mockito.any());
    Mockito.verify(facade, Mockito.never()).archiveKey(Mockito.eq("good-2"), Mockito.any());
    Mockito.verify(facade, Mockito.times(1)).archiveKey(Mockito.eq("old-1"), Mockito.any());

    Mockito.verify(hsmService, Mockito.never()).deleteKey("good-1");
    Mockito.verify(hsmService, Mockito.never()).deleteKey("good-2");
    Mockito.verify(hsmService, Mockito.never()).deleteKey("old-1");

    Mockito.verify(hsmService, Mockito.never()).exportKey("good-1");
    Mockito.verify(hsmService, Mockito.never()).exportKey("good-2");
    Mockito.verify(hsmService, Mockito.times(1)).exportKey("old-1");
  }


  /**
   * We override the warmup method to prevent initialization/warming-up of a real HSM. Since this happens in the
   * constructor - it cannot be easily mocked otherwise.
   */
  private static class HsmServiceHolderTestWrapper extends HSMServiceHolder
  {

    public HsmServiceHolderTestWrapper(String hsmTypeStr,
                                       int deleteOldKeys,
                                       boolean archiveOldKeys,
                                       TerminalPermissionAO facade)
    {
      super(hsmTypeStr, "NOOP", "NOOP", deleteOldKeys, archiveOldKeys, facade);
    }

    @Override
    public final List<ManagementMessage> warmingUp()
    {
      return List.of();
    }
  }
}

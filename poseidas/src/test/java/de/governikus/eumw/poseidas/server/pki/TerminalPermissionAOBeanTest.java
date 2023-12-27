/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.pki;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.locks.ReentrantLock;

import jakarta.xml.bind.DatatypeConverter;

import org.apache.commons.lang3.ArrayUtils;
import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.joda.time.DateTime;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.mockito.stubbing.Answer;
import org.springframework.data.domain.Sort;

import com.google.common.io.ByteStreams;

import de.governikus.eumw.config.EidasMiddlewareConfig;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationService;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationTestHelper;


class TerminalPermissionAOBeanTest
{

  private static final String SERVICE_PROVIDER = "serviceProvider";

  private static final int MINUTE = 1000 * 60;

  @Test
  void getTerminalPermission()
  {
    TerminalPermissionRepository terminalPermissionRepository = Mockito.mock(TerminalPermissionRepository.class);
    TerminalPermissionAOBean terminalPermissionAOBean = new TerminalPermissionAOBean(terminalPermissionRepository,
                                                                                     null, null, null, null,
                                                                                     null, null, null, null);

    String refID = "refID";
    Assertions.assertNull(terminalPermissionAOBean.getTerminalPermission(null));
    Assertions.assertNull(terminalPermissionAOBean.getTerminalPermission(refID));

    TerminalPermission terminalPermission = new TerminalPermission(refID);
    Mockito.when(terminalPermissionRepository.findById(refID)).thenReturn(Optional.of(terminalPermission));
    Assertions.assertEquals(terminalPermission, terminalPermissionAOBean.getTerminalPermission(refID));
  }

  @Test
  void getExpirationDates()
  {
    TerminalPermissionRepository terminalPermissionRepository = Mockito.mock(TerminalPermissionRepository.class);
    TerminalPermissionAOBean terminalPermissionAOBean = new TerminalPermissionAOBean(terminalPermissionRepository,
                                                                                     null, null, null, null,
                                                                                     null, null, null, null);

    Assertions.assertEquals(0, terminalPermissionAOBean.getExpirationDates().size());

    TerminalPermission empty = new TerminalPermission();
    TerminalPermission first = new TerminalPermission("first");
    first.setNotOnOrAfter(DateTime.now().toDate());
    TerminalPermission second = new TerminalPermission("second");
    second.setNotOnOrAfter(DateTime.now().toDate());
    List<TerminalPermission> terminals = new ArrayList<>(Arrays.asList(empty, first, second));
    Mockito.when(terminalPermissionRepository.findAll(Mockito.any(Sort.class))).thenReturn(terminals);

    MatcherAssert.assertThat(terminalPermissionAOBean.getExpirationDates(), Matchers.aMapWithSize(2));
    MatcherAssert.assertThat(terminalPermissionAOBean.getExpirationDates(),
                             Matchers.hasKey(first.getRefID()));
    MatcherAssert.assertThat(terminalPermissionAOBean.getExpirationDates(),
                             Matchers.hasKey(second.getRefID()));
  }

  @Test
  void obtainCVCUpdateLock()
  {
    CVCUpdateLockRepository cvcUpdateLockRepository = Mockito.mock(CVCUpdateLockRepository.class);
    TerminalPermissionAOBean terminalPermissionAOBean = new TerminalPermissionAOBean(null, null, null,
                                                                                     cvcUpdateLockRepository,
                                                                                     null, null, null, null,
                                                                                     null);

    // No lock
    CVCUpdateLock obtainedLock = terminalPermissionAOBean.obtainCVCUpdateLock(SERVICE_PROVIDER);
    Assertions.assertNotNull(obtainedLock);
    Assertions.assertTrue(obtainedLock.getLockedAt() > System.currentTimeMillis() - MINUTE);
    Mockito.verify(cvcUpdateLockRepository).save(Mockito.any());
    Mockito.reset(cvcUpdateLockRepository);

    // Fresh lock without stealing
    CVCUpdateLock freshLock = new CVCUpdateLock(SERVICE_PROVIDER, System.currentTimeMillis() - MINUTE);
    Mockito.when(cvcUpdateLockRepository.findById(Mockito.anyString())).thenReturn(Optional.of(freshLock));
    obtainedLock = terminalPermissionAOBean.obtainCVCUpdateLock(SERVICE_PROVIDER);
    Assertions.assertNull(obtainedLock);
    Mockito.verify(cvcUpdateLockRepository, Mockito.never()).save(Mockito.any());
    Mockito.reset(cvcUpdateLockRepository);

    // Old lock that is stolen
    CVCUpdateLock oldLock = new CVCUpdateLock(SERVICE_PROVIDER, System.currentTimeMillis() - 60 * MINUTE);
    Mockito.when(cvcUpdateLockRepository.findById(Mockito.anyString())).thenReturn(Optional.of(oldLock));
    obtainedLock = terminalPermissionAOBean.obtainCVCUpdateLock(SERVICE_PROVIDER);
    Assertions.assertNotNull(obtainedLock);
    Assertions.assertTrue(obtainedLock.getLockedAt() > System.currentTimeMillis() - MINUTE);
    Mockito.verify(cvcUpdateLockRepository).save(Mockito.any());
  }

  @Test
  void releaseCVCUpdateLock()
  {
    CVCUpdateLockRepository cvcUpdateLockRepository = Mockito.mock(CVCUpdateLockRepository.class);
    TerminalPermissionAOBean terminalPermissionAOBean = new TerminalPermissionAOBean(null, null, null,
                                                                                     cvcUpdateLockRepository,
                                                                                     null, null, null, null,
                                                                                     null);


    Assertions.assertThrows(IllegalArgumentException.class,
                            () -> terminalPermissionAOBean.releaseCVCUpdateLock(null));

    // Unknown lock
    CVCUpdateLock cvcUpdateLock = new CVCUpdateLock(SERVICE_PROVIDER, System.currentTimeMillis());
    Assertions.assertFalse(terminalPermissionAOBean.releaseCVCUpdateLock(cvcUpdateLock));
    Mockito.verify(cvcUpdateLockRepository, Mockito.never()).delete(Mockito.any());

    // Current lock
    Mockito.when(cvcUpdateLockRepository.findById(SERVICE_PROVIDER)).thenReturn(Optional.of(cvcUpdateLock));
    Assertions.assertTrue(terminalPermissionAOBean.releaseCVCUpdateLock(cvcUpdateLock));
    Mockito.verify(cvcUpdateLockRepository, Mockito.times(1)).delete(Mockito.any());
    Mockito.clearInvocations(cvcUpdateLockRepository);

    // Stolen lock
    CVCUpdateLock oldLock = new CVCUpdateLock(SERVICE_PROVIDER, System.currentTimeMillis() - MINUTE);
    Assertions.assertFalse(terminalPermissionAOBean.releaseCVCUpdateLock(oldLock));
    Mockito.verify(cvcUpdateLockRepository, Mockito.never()).delete(Mockito.any());
  }

  @Test
  void updateBlackListStoreDate()
  {
    TerminalPermissionRepository terminalPermissionRepository = Mockito.mock(TerminalPermissionRepository.class);
    TerminalPermissionAOBean terminalPermissionAOBean = new TerminalPermissionAOBean(terminalPermissionRepository,
                                                                                     null, null, null, null,
                                                                                     null, null, null, null);

    // Null and unknown refID
    terminalPermissionAOBean.updateBlackListStoreDate(null, null, 0L);
    terminalPermissionAOBean.updateBlackListStoreDate(SERVICE_PROVIDER, null, 0L);
    Mockito.verify(terminalPermissionRepository, Mockito.never()).save(Mockito.any());

    // Mock the TerminalPermission entry
    Mockito.when(terminalPermissionRepository.findById(Mockito.anyString()))
           .thenReturn(Optional.of(new TerminalPermission(SERVICE_PROVIDER)));
    // Mock save method to assert that the object to be saved was correctly created by
    // TerminalPermissionAOBean
    Mockito.when(terminalPermissionRepository.save(Mockito.any()))
           .thenAnswer((Answer<TerminalPermission>)invocation -> {
             Object[] args = invocation.getArguments();
             TerminalPermission terminalPermission = (TerminalPermission)args[0];
             Assertions.assertEquals(SERVICE_PROVIDER, terminalPermission.getRefID());
             Assertions.assertArrayEquals(SERVICE_PROVIDER.getBytes(StandardCharsets.UTF_8),
                                          terminalPermission.getSectorID());
             Assertions.assertEquals(1L, terminalPermission.getBlackListVersion());
             Assertions.assertTrue(terminalPermission.getBlackListStoreDate()
                                                     .after(DateTime.now().minus(MINUTE).toDate()));
             return terminalPermission;
           });
    // Actual update
    terminalPermissionAOBean.updateBlackListStoreDate(SERVICE_PROVIDER,
                                                      SERVICE_PROVIDER.getBytes(StandardCharsets.UTF_8),
                                                      1L);
    Mockito.verify(terminalPermissionRepository).save(Mockito.any());
  }

  @Test
  void removeSpecificIDs()
  {
    List<String> fakeBlackListRepoContent = new ArrayList<>();
    for ( int i = 0 ; i < 3000 ; i++ )
    {
      fakeBlackListRepoContent.add(String.valueOf(i));
    }
    List<String> entriesToBeDeleted = new ArrayList<>();
    for ( int i = 0 ; i < 2000 ; i++ )
    {
      entriesToBeDeleted.add(String.valueOf(i));
    }
    String sectorId = "sectorId";

    BlackListEntryRepository blackListEntryRepository = Mockito.mock(BlackListEntryRepository.class);
    TerminalPermissionAOBean terminalPermissionAOBean = new TerminalPermissionAOBean(null, null, null, null,
                                                                                     blackListEntryRepository,
                                                                                     null, null, null, null);
    // A lock must be used because parallelStream()... is leading to non-deterministic behaviour while
    // removing from the same list
    ReentrantLock deletionLock = new ReentrantLock();
    Mockito.doAnswer(invocation -> {
      String sectorIdDeleted = invocation.getArgument(0);
      List<String> toBeDeleted = invocation.getArgument(1);
      Assertions.assertEquals(sectorId, sectorIdDeleted);
      deletionLock.lock();
      for ( String entry : toBeDeleted )
      {
        Assertions.assertTrue(fakeBlackListRepoContent.remove(entry));
      }
      deletionLock.unlock();
      return null;
    })
           .when(blackListEntryRepository)
           .deleteAllByKey_SectorIDAndKey_SpecificIDIn(Mockito.anyString(), Mockito.anyList());

    terminalPermissionAOBean.removeSpecificIDs(sectorId, entriesToBeDeleted);
    Assertions.assertEquals(1000, fakeBlackListRepoContent.size());
  }

  @Test
  void storeCVCRequestSent()
  {
    TerminalPermissionRepository terminalPermissionRepository = Mockito.mock(TerminalPermissionRepository.class);
    TerminalPermissionAOBean terminalPermissionAOBean = new TerminalPermissionAOBean(terminalPermissionRepository,
                                                                                     null, null, null, null,
                                                                                     null, null, null, null);

    terminalPermissionAOBean.storeCVCRequestSent(null);
    terminalPermissionAOBean.storeCVCRequestSent(SERVICE_PROVIDER);
    Mockito.verify(terminalPermissionRepository, Mockito.never()).saveAndFlush(Mockito.any());

    // Prepare mocked TerminalPermission Entry
    TerminalPermission terminalPermission = new TerminalPermission(SERVICE_PROVIDER);
    terminalPermission.setPendingRequest(new PendingCertificateRequest(SERVICE_PROVIDER));
    Mockito.when(terminalPermissionRepository.findById(Mockito.anyString()))
           .thenReturn(Optional.of(terminalPermission));
    // Mock saveAndFlush to assert for TerminalPermission changes
    Mockito.doAnswer(invocationOnMock -> {
      TerminalPermission invocationOnMockArgument = invocationOnMock.getArgument(0);
      Assertions.assertEquals(PendingCertificateRequest.Status.SENT,
                              invocationOnMockArgument.getPendingRequest().getStatus());
      return null;
    }).when(terminalPermissionRepository).saveAndFlush(Mockito.any());

    terminalPermissionAOBean.storeCVCRequestSent(SERVICE_PROVIDER);
    Mockito.verify(terminalPermissionRepository).saveAndFlush(Mockito.any());
  }

  @Test
  void deleteCVCRequest()
  {
    TerminalPermissionRepository terminalPermissionRepository = Mockito.mock(TerminalPermissionRepository.class);
    PendingCertificateRequestRepository pendingCertificateRequestRepository = Mockito.mock(PendingCertificateRequestRepository.class);
    TerminalPermissionAOBean terminalPermissionAOBean = new TerminalPermissionAOBean(terminalPermissionRepository,
                                                                                     null, null, null, null,
                                                                                     pendingCertificateRequestRepository,
                                                                                     null, null, null);

    terminalPermissionAOBean.deleteCVCRequest(null);
    terminalPermissionAOBean.deleteCVCRequest(SERVICE_PROVIDER);
    Mockito.verify(terminalPermissionRepository, Mockito.never()).saveAndFlush(Mockito.any());
    Mockito.verify(pendingCertificateRequestRepository, Mockito.never()).delete(Mockito.any());

    // Prepare mocked TerminalPermission Entry but without pendingRequest
    TerminalPermission terminalPermission = new TerminalPermission(SERVICE_PROVIDER);
    Mockito.when(terminalPermissionRepository.findById(Mockito.anyString()))
           .thenReturn(Optional.of(terminalPermission));

    terminalPermissionAOBean.deleteCVCRequest(SERVICE_PROVIDER);
    Mockito.verify(terminalPermissionRepository, Mockito.never()).saveAndFlush(Mockito.any());
    Mockito.verify(pendingCertificateRequestRepository, Mockito.never()).delete(Mockito.any());

    // Add pendingRequest to entry
    PendingCertificateRequest pendingRequest = new PendingCertificateRequest(SERVICE_PROVIDER);
    terminalPermission.setPendingRequest(pendingRequest);

    // Mock saveAndFlush to assert for TerminalPermission changes
    Mockito.doAnswer(invocationOnMock -> {
      TerminalPermission invocationOnMockArgument = invocationOnMock.getArgument(0);
      Assertions.assertNull(invocationOnMockArgument.getPendingRequest());
      return null;
    }).when(terminalPermissionRepository).saveAndFlush(Mockito.any());
    // Mock delete to assert for correct PendingRequest
    Mockito.doAnswer(invocationOnMock -> {
      PendingCertificateRequest invocationOnMockArgument = invocationOnMock.getArgument(0);
      Assertions.assertEquals(pendingRequest, invocationOnMockArgument);
      return null;
    }).when(pendingCertificateRequestRepository).delete(Mockito.any());

    terminalPermissionAOBean.deleteCVCRequest(SERVICE_PROVIDER);
    Mockito.verify(terminalPermissionRepository).saveAndFlush(Mockito.any());
    Mockito.verify(pendingCertificateRequestRepository).delete(Mockito.any());
  }


  @Test
  void removeTerminalPermission()
  {
    TerminalPermissionRepository terminalPermissionRepository = Mockito.mock(TerminalPermissionRepository.class);
    CertInChainRepository certInChainRepository = Mockito.mock(CertInChainRepository.class);
    PendingCertificateRequestRepository pendingCertificateRequestRepository = Mockito.mock(PendingCertificateRequestRepository.class);
    BlackListEntryRepository blackListEntryRepository = Mockito.mock(BlackListEntryRepository.class);
    CertInChain certInChain = Mockito.mock(CertInChain.class);
    PendingCertificateRequest pendingCertificateRequest = Mockito.mock(PendingCertificateRequest.class);
    TerminalPermissionAOBean terminalPermissionAOBean = new TerminalPermissionAOBean(terminalPermissionRepository,
                                                                                     null,
                                                                                     certInChainRepository,
                                                                                     null,
                                                                                     blackListEntryRepository,
                                                                                     pendingCertificateRequestRepository,
                                                                                     null, null, null);
    // No Terminal Permission
    Mockito.when(terminalPermissionRepository.findById(Mockito.anyString())).thenReturn(Optional.empty());

    Assertions.assertFalse(terminalPermissionAOBean.remove(SERVICE_PROVIDER));
    Mockito.verify(certInChainRepository, Mockito.never()).delete(certInChain);
    Mockito.verify(pendingCertificateRequestRepository, Mockito.never()).delete(pendingCertificateRequest);
    Mockito.verify(blackListEntryRepository, Mockito.never()).deleteAllByKey_SectorID(Mockito.anyString());

    // Without certs in chain, pending request and sector id
    TerminalPermission terminalPermission = new TerminalPermission(SERVICE_PROVIDER);
    Mockito.when(terminalPermissionRepository.findById(SERVICE_PROVIDER))
           .thenReturn(Optional.of(terminalPermission));

    Assertions.assertTrue(terminalPermissionAOBean.remove(SERVICE_PROVIDER));
    Mockito.verify(certInChainRepository, Mockito.never()).delete(certInChain);
    Mockito.verify(pendingCertificateRequestRepository, Mockito.never()).delete(pendingCertificateRequest);
    Mockito.verify(blackListEntryRepository, Mockito.never()).deleteAllByKey_SectorID(Mockito.anyString());

    // With certs in chain, pending request and sector id
    terminalPermission.getChain().add(certInChain);
    terminalPermission.setPendingRequest(pendingCertificateRequest);
    terminalPermission.setSectorID("sectorId".getBytes());

    Assertions.assertTrue(terminalPermissionAOBean.remove(SERVICE_PROVIDER));
    Mockito.verify(certInChainRepository).delete(certInChain);
    Mockito.verify(pendingCertificateRequestRepository).delete(pendingCertificateRequest);
    Mockito.verify(blackListEntryRepository)
           .deleteAllByKey_SectorID(DatatypeConverter.printBase64Binary("sectorId".getBytes()));
  }

  @Test
  void releaseChangeKeyLock() throws Exception
  {
    ChangeKeyLockRepository changeKeyLockRepository = Mockito.mock(ChangeKeyLockRepository.class);
    TerminalPermissionAOBean terminalPermissionAOBean = new TerminalPermissionAOBean(null, null, null, null,
                                                                                     null, null,
                                                                                     changeKeyLockRepository,
                                                                                     null, null);
    long now = System.currentTimeMillis();
    String myAddress = "localhost";
    ChangeKeyLock changeKeyLock = new ChangeKeyLock("keyName", myAddress, now, 0);

    // Without terminal permission
    ChangeKeyLock changeKeyLockMock = Mockito.mock(ChangeKeyLock.class);
    Mockito.when(changeKeyLockRepository.findById(Mockito.anyString())).thenReturn(Optional.empty());

    Assertions.assertFalse(terminalPermissionAOBean.releaseChangeKeyLock(changeKeyLock));
    Mockito.verify(changeKeyLockRepository, Mockito.never()).delete(changeKeyLockMock);

    // With terminal permission
    Mockito.when(changeKeyLockRepository.findById(Mockito.anyString()))
           .thenReturn(Optional.of(changeKeyLockMock));

    Assertions.assertTrue(terminalPermissionAOBean.releaseChangeKeyLock(changeKeyLock));
    Mockito.verify(changeKeyLockRepository).delete(changeKeyLockMock);
  }

  @Test
  void releaseChangeLockOwner() throws Exception
  {
    ChangeKeyLockRepository changeKeyLockRepository = Mockito.mock(ChangeKeyLockRepository.class);
    TerminalPermissionAOBean terminalPermissionAOBean = new TerminalPermissionAOBean(null, null, null, null,
                                                                                     null, null,
                                                                                     changeKeyLockRepository,
                                                                                     null, null);
    long now = System.currentTimeMillis();
    String myAddress = "localhost";
    ChangeKeyLock changeKeyLock = new ChangeKeyLock("keyName", myAddress, now, 0);
    ChangeKeyLock changeKeyLockMock = Mockito.mock(ChangeKeyLock.class);

    // Without terminal permission
    Mockito.when(changeKeyLockRepository.findById(Mockito.anyString())).thenReturn(Optional.empty());

    Assertions.assertFalse(terminalPermissionAOBean.releaseChangeKeyLockOwner(changeKeyLock));
    Mockito.verify(changeKeyLockRepository, Mockito.never()).save(changeKeyLockMock);

    // With terminal permission
    Mockito.when(changeKeyLockRepository.findById(Mockito.anyString()))
           .thenReturn(Optional.of(changeKeyLockMock));

    Assertions.assertTrue(terminalPermissionAOBean.releaseChangeKeyLockOwner(changeKeyLock));
    Mockito.doAnswer(invocation -> {
      String autentIP = invocation.getArgument(0);
      Assertions.assertEquals("VOID", autentIP);
      return null;
    }).when(changeKeyLockMock).setAutentIP(Mockito.anyString());
    Mockito.verify(changeKeyLockRepository).save(changeKeyLockMock);
  }

  @Test
  void storeCVCObtainedWithCvcDescription() throws Exception
  {
    TerminalPermissionRepository terminalPermissionRepository = Mockito.mock(TerminalPermissionRepository.class);
    PendingCertificateRequestRepository pendingCertificateRequestRepository = Mockito.mock(PendingCertificateRequestRepository.class);
    CertInChainRepository certInChainRepository = Mockito.mock(CertInChainRepository.class);
    PendingCertificateRequest pendingCertificateRequest = Mockito.mock(PendingCertificateRequest.class);
    TerminalPermissionAOBean terminalPermissionAOBean = new TerminalPermissionAOBean(terminalPermissionRepository,
                                                                                     null,
                                                                                     certInChainRepository,
                                                                                     null, null,
                                                                                     pendingCertificateRequestRepository,
                                                                                     null, null, null);
    byte[] cvc = getResourceAsByteArray("/terminalCertificates/terminalCert.cvc");
    byte[] cvcDescription = ArrayUtils.EMPTY_BYTE_ARRAY;
    byte[] privateKey = ArrayUtils.EMPTY_BYTE_ARRAY;

    Mockito.when(terminalPermissionRepository.findById(Mockito.anyString())).thenReturn(Optional.empty());
    terminalPermissionAOBean.storeCVCObtained(SERVICE_PROVIDER, cvc, null, cvcDescription);
    Mockito.verifyNoInteractions(pendingCertificateRequestRepository);
    Mockito.verifyNoInteractions(certInChainRepository);
    TerminalPermission terminalPermission = new TerminalPermission(SERVICE_PROVIDER);
    terminalPermission.setPendingRequest(pendingCertificateRequest);
    Mockito.when(pendingCertificateRequest.getPrivateKey()).thenReturn(privateKey);
    Mockito.when(terminalPermissionRepository.findById(Mockito.anyString()))
           .thenReturn(Optional.of(terminalPermission));
    Mockito.doAnswer(invocation -> {
      PendingCertificateRequest pendingCertificateRequestMock = invocation.getArgument(0);
      Assertions.assertEquals(pendingCertificateRequest, pendingCertificateRequestMock);
      return null;
    }).when(pendingCertificateRequestRepository).delete(Mockito.any());
    terminalPermissionAOBean.storeCVCObtained(SERVICE_PROVIDER, cvc, null, cvcDescription);

    Mockito.verify(pendingCertificateRequestRepository).delete(pendingCertificateRequest);
    Mockito.verifyNoInteractions(certInChainRepository);
    Assertions.assertEquals(cvc, terminalPermission.getCvc());
    Assertions.assertEquals(privateKey, terminalPermission.getCvcPrivateKey());
    Assertions.assertEquals(cvcDescription, terminalPermission.getCvcDescription());
    Assertions.assertNull(terminalPermission.getPendingRequest());
  }

  @Test
  void storeCVCObtainedWithoutCvcDescription() throws Exception
  {
    TerminalPermissionRepository terminalPermissionRepository = Mockito.mock(TerminalPermissionRepository.class);
    PendingCertificateRequestRepository pendingCertificateRequestRepository = Mockito.mock(PendingCertificateRequestRepository.class);
    CertInChainRepository certInChainRepository = Mockito.mock(CertInChainRepository.class);
    PendingCertificateRequest pendingCertificateRequest = Mockito.mock(PendingCertificateRequest.class);
    TerminalPermissionAOBean terminalPermissionAOBean = new TerminalPermissionAOBean(terminalPermissionRepository,
                                                                                     null,
                                                                                     certInChainRepository,
                                                                                     null, null,
                                                                                     pendingCertificateRequestRepository,
                                                                                     null, null, null);
    byte[] cvc = getResourceAsByteArray("/terminalCertificates/terminalCert.cvc");
    byte[] privateKey = ArrayUtils.EMPTY_BYTE_ARRAY;
    TerminalPermission terminalPermission = new TerminalPermission(SERVICE_PROVIDER);
    terminalPermission.setPendingRequest(pendingCertificateRequest);

    Mockito.when(terminalPermissionRepository.findById(Mockito.anyString()))
           .thenReturn(Optional.of(terminalPermission));
    Mockito.when(pendingCertificateRequest.getPrivateKey()).thenReturn(privateKey);
    terminalPermissionAOBean.storeCVCObtained(SERVICE_PROVIDER, cvc, null, null);

    Mockito.verify(pendingCertificateRequest).getNewCvcDescription();
    Mockito.verify(pendingCertificateRequestRepository).delete(pendingCertificateRequest);
    Mockito.verifyNoInteractions(certInChainRepository);
    Assertions.assertEquals(cvc, terminalPermission.getCvc());
    Assertions.assertEquals(privateKey, terminalPermission.getCvcPrivateKey());
    Assertions.assertNull(terminalPermission.getCvcDescription());
    Assertions.assertNull(terminalPermission.getPendingRequest());
  }

  @Test
  void storeCVCObtainedWithCvcDescriptionFromPendingRequest() throws Exception
  {
    TerminalPermissionRepository terminalPermissionRepository = Mockito.mock(TerminalPermissionRepository.class);
    PendingCertificateRequestRepository pendingCertificateRequestRepository = Mockito.mock(PendingCertificateRequestRepository.class);
    CertInChainRepository certInChainRepository = Mockito.mock(CertInChainRepository.class);
    PendingCertificateRequest pendingCertificateRequest = Mockito.mock(PendingCertificateRequest.class);
    TerminalPermissionAOBean terminalPermissionAOBean = new TerminalPermissionAOBean(terminalPermissionRepository,
                                                                                     null,
                                                                                     certInChainRepository,
                                                                                     null, null,
                                                                                     pendingCertificateRequestRepository,
                                                                                     null, null, null);
    byte[] cvc = getResourceAsByteArray("/terminalCertificates/terminalCert.cvc");
    byte[] privateKey = ArrayUtils.EMPTY_BYTE_ARRAY;
    byte[] cvcDescription = ArrayUtils.EMPTY_BYTE_ARRAY;
    TerminalPermission terminalPermission = new TerminalPermission(SERVICE_PROVIDER);
    terminalPermission.setPendingRequest(pendingCertificateRequest);

    Mockito.when(terminalPermissionRepository.findById(Mockito.anyString()))
           .thenReturn(Optional.of(terminalPermission));
    Mockito.when(pendingCertificateRequest.getPrivateKey()).thenReturn(privateKey);
    Mockito.when(pendingCertificateRequest.getNewCvcDescription()).thenReturn(cvcDescription);
    terminalPermissionAOBean.storeCVCObtained(SERVICE_PROVIDER, cvc, null, null);

    Mockito.verify(pendingCertificateRequest, Mockito.times(2)).getNewCvcDescription();
    Mockito.verify(pendingCertificateRequestRepository).delete(pendingCertificateRequest);
    Mockito.verifyNoInteractions(certInChainRepository);
    Assertions.assertEquals(cvc, terminalPermission.getCvc());
    Assertions.assertEquals(privateKey, terminalPermission.getCvcPrivateKey());
    Assertions.assertEquals(cvcDescription, terminalPermission.getCvcDescription());
    Assertions.assertNull(terminalPermission.getPendingRequest());
  }

  @Test
  void storeCvcObtainedWithChain() throws Exception
  {
    TerminalPermissionRepository terminalPermissionRepository = Mockito.mock(TerminalPermissionRepository.class);
    PendingCertificateRequestRepository pendingCertificateRequestRepository = Mockito.mock(PendingCertificateRequestRepository.class);
    CertInChainRepository certInChainRepository = Mockito.mock(CertInChainRepository.class);
    PendingCertificateRequest pendingCertificateRequest = Mockito.mock(PendingCertificateRequest.class);
    TerminalPermissionAOBean terminalPermissionAOBean = new TerminalPermissionAOBean(terminalPermissionRepository,
                                                                                     null,
                                                                                     certInChainRepository,
                                                                                     null, null,
                                                                                     pendingCertificateRequestRepository,
                                                                                     null, null, null);
    byte[] cvc = getResourceAsByteArray("/terminalCertificates/terminalCert.cvc");
    byte[] chain0 = getResourceAsByteArray("/terminalCertificates/chain0.crt");
    byte[] chain1 = getResourceAsByteArray("/terminalCertificates/chain1.crt");
    byte[] cvcDescription = ArrayUtils.EMPTY_BYTE_ARRAY;
    byte[] privateKey = ArrayUtils.EMPTY_BYTE_ARRAY;
    List<byte[]> chainList = Arrays.asList(chain0, chain1);
    byte[][] chain = chainList.toArray(new byte[0][]);
    TerminalPermission terminalPermission = new TerminalPermission(SERVICE_PROVIDER);
    CertInChain certInChainPresent = new CertInChain(terminalPermission,
                                                     new CertInChainPK(terminalPermission.getRefID(), 0),
                                                     chain0);
    CertInChain certInChainOld = new CertInChain(terminalPermission,
                                                 new CertInChainPK(terminalPermission.getRefID(), 4),
                                                 ArrayUtils.EMPTY_BYTE_ARRAY);
    terminalPermission.getChain().add(certInChainPresent);
    terminalPermission.getChain().add(certInChainOld);
    terminalPermission.setPendingRequest(pendingCertificateRequest);

    Mockito.when(terminalPermissionRepository.findById(Mockito.anyString()))
           .thenReturn(Optional.of(terminalPermission));
    Mockito.when(pendingCertificateRequest.getPrivateKey()).thenReturn(privateKey);
    terminalPermissionAOBean.storeCVCObtained(SERVICE_PROVIDER, cvc, chain, cvcDescription);

    Mockito.verify(pendingCertificateRequestRepository).delete(pendingCertificateRequest);
    Mockito.verify(certInChainRepository, Mockito.times(2)).save(Mockito.any());
    Mockito.verify(certInChainRepository).delete(certInChainOld);
    Assertions.assertEquals(cvc, terminalPermission.getCvc());
    Assertions.assertEquals(privateKey, terminalPermission.getCvcPrivateKey());
    Assertions.assertEquals(cvcDescription, terminalPermission.getCvcDescription());
    Assertions.assertNull(terminalPermission.getPendingRequest());
    Assertions.assertEquals(2, terminalPermission.getChain().size());
  }

  @Test
  void storeCvcObtainedWithCorruptCvc()
  {
    TerminalPermissionRepository terminalPermissionRepository = Mockito.mock(TerminalPermissionRepository.class);
    PendingCertificateRequestRepository pendingCertificateRequestRepository = Mockito.mock(PendingCertificateRequestRepository.class);
    CertInChainRepository certInChainRepository = Mockito.mock(CertInChainRepository.class);
    PendingCertificateRequest pendingCertificateRequest = Mockito.mock(PendingCertificateRequest.class);
    TerminalPermissionAOBean terminalPermissionAOBean = new TerminalPermissionAOBean(terminalPermissionRepository,
                                                                                     null,
                                                                                     certInChainRepository,
                                                                                     null, null,
                                                                                     pendingCertificateRequestRepository,
                                                                                     null, null, null);
    byte[] cvc = ArrayUtils.EMPTY_BYTE_ARRAY;
    byte[] privateKey = ArrayUtils.EMPTY_BYTE_ARRAY;
    TerminalPermission terminalPermission = new TerminalPermission(SERVICE_PROVIDER);
    terminalPermission.setPendingRequest(pendingCertificateRequest);
    Mockito.when(terminalPermissionRepository.findById(Mockito.anyString()))
           .thenReturn(Optional.of(terminalPermission));
    Mockito.when(pendingCertificateRequest.getPrivateKey()).thenReturn(privateKey);
    terminalPermissionAOBean.storeCVCObtained(SERVICE_PROVIDER, cvc, null, null);
    Mockito.verify(pendingCertificateRequestRepository).delete(pendingCertificateRequest);
    Mockito.verifyNoInteractions(certInChainRepository);
    Assertions.assertEquals(cvc, terminalPermission.getCvc());
    Assertions.assertNull(terminalPermission.getPendingRequest());
    Assertions.assertNull(terminalPermission.getCvcDescription());
  }

  @Test
  void storeCvcRequestCreatedWithoutPendingRequest()
  {
    TerminalPermissionRepository terminalPermissionRepository = Mockito.mock(TerminalPermissionRepository.class);
    PendingCertificateRequestRepository pendingCertificateRequestRepository = Mockito.mock(PendingCertificateRequestRepository.class);
    CertInChainRepository certInChainRepository = Mockito.mock(CertInChainRepository.class);
    TerminalPermissionAOBean terminalPermissionAOBean = new TerminalPermissionAOBean(terminalPermissionRepository,
                                                                                     null,
                                                                                     certInChainRepository,
                                                                                     null, null,
                                                                                     pendingCertificateRequestRepository,
                                                                                     null, null, null);
    byte[] request = ArrayUtils.EMPTY_BYTE_ARRAY;
    byte[] cvcDescription = ArrayUtils.EMPTY_BYTE_ARRAY;
    byte[] privateKey = ArrayUtils.EMPTY_BYTE_ARRAY;

    Mockito.when(terminalPermissionRepository.findById(Mockito.anyString())).thenReturn(Optional.empty());
    terminalPermissionAOBean.storeCVCRequestCreated(SERVICE_PROVIDER,
                                                    "messageId",
                                                    request,
                                                    cvcDescription,
                                                    null,
                                                    privateKey);

    Mockito.verifyNoInteractions(pendingCertificateRequestRepository);
    Mockito.verifyNoInteractions(certInChainRepository);
    Mockito.verify(terminalPermissionRepository, Mockito.never()).saveAndFlush(Mockito.any());

    TerminalPermission terminalPermission = new TerminalPermission(SERVICE_PROVIDER);
    Mockito.when(terminalPermissionRepository.findById(Mockito.anyString()))
           .thenReturn(Optional.of(terminalPermission));

    terminalPermissionAOBean.storeCVCRequestCreated(SERVICE_PROVIDER,
                                                    "messageId",
                                                    request,
                                                    cvcDescription,
                                                    null,
                                                    privateKey);
    Assertions.assertNotNull(terminalPermission.getPendingRequest());
    Assertions.assertEquals(request, terminalPermission.getPendingRequest().getRequestData());
    Assertions.assertEquals(cvcDescription, terminalPermission.getPendingRequest().getNewCvcDescription());
    Assertions.assertEquals(privateKey, terminalPermission.getPendingRequest().getPrivateKey());
    Assertions.assertEquals("messageId", terminalPermission.getPendingRequest().getMessageID());
    Mockito.verify(pendingCertificateRequestRepository, Mockito.times(2)).saveAndFlush(Mockito.any());
    Mockito.verify(terminalPermissionRepository).saveAndFlush(terminalPermission);
  }

  @Test
  void storeCvcRequestWithPendingRequest()
  {
    TerminalPermissionRepository terminalPermissionRepository = Mockito.mock(TerminalPermissionRepository.class);
    PendingCertificateRequestRepository pendingCertificateRequestRepository = Mockito.mock(PendingCertificateRequestRepository.class);
    CertInChainRepository certInChainRepository = Mockito.mock(CertInChainRepository.class);
    PendingCertificateRequest pendingCertificateRequest = Mockito.mock(PendingCertificateRequest.class);
    TerminalPermissionAOBean terminalPermissionAOBean = new TerminalPermissionAOBean(terminalPermissionRepository,
                                                                                     null,
                                                                                     certInChainRepository,
                                                                                     null, null,
                                                                                     pendingCertificateRequestRepository,
                                                                                     null, null, null);
    byte[] request = ArrayUtils.EMPTY_BYTE_ARRAY;
    byte[] cvcDescription = ArrayUtils.EMPTY_BYTE_ARRAY;
    byte[] privateKey = ArrayUtils.EMPTY_BYTE_ARRAY;

    TerminalPermission terminalPermission = new TerminalPermission(SERVICE_PROVIDER);
    terminalPermission.setPendingRequest(pendingCertificateRequest);
    Mockito.when(terminalPermissionRepository.findById(Mockito.anyString()))
           .thenReturn(Optional.of(terminalPermission));
    Mockito.doAnswer(invocation -> {
      PendingCertificateRequest.Status pendingRequestStatus = invocation.getArgument(0);
      Assertions.assertEquals(PendingCertificateRequest.Status.CREATED, pendingRequestStatus);
      return null;
    }).when(pendingCertificateRequest).setStatus(Mockito.any());
    terminalPermissionAOBean.storeCVCRequestCreated(SERVICE_PROVIDER,
                                                    "messageId",
                                                    request,
                                                    cvcDescription,
                                                    null,
                                                    privateKey);
    Mockito.verify(pendingCertificateRequestRepository).saveAndFlush(pendingCertificateRequest);
    Mockito.verify(terminalPermissionRepository).saveAndFlush(terminalPermission);
    Mockito.verifyNoInteractions(certInChainRepository);
  }

  @Test
  void storeCvcRequestWithChain() throws Exception
  {
    TerminalPermissionRepository terminalPermissionRepository = Mockito.mock(TerminalPermissionRepository.class);
    PendingCertificateRequestRepository pendingCertificateRequestRepository = Mockito.mock(PendingCertificateRequestRepository.class);
    CertInChainRepository certInChainRepository = Mockito.mock(CertInChainRepository.class);
    PendingCertificateRequest pendingCertificateRequest = Mockito.mock(PendingCertificateRequest.class);
    TerminalPermissionAOBean terminalPermissionAOBean = new TerminalPermissionAOBean(terminalPermissionRepository,
                                                                                     null,
                                                                                     certInChainRepository,
                                                                                     null, null,
                                                                                     pendingCertificateRequestRepository,
                                                                                     null, null, null);
    byte[] chain0 = getResourceAsByteArray("/terminalCertificates/chain0.crt");
    byte[] chain1 = getResourceAsByteArray("/terminalCertificates/chain1.crt");
    byte[] request = ArrayUtils.EMPTY_BYTE_ARRAY;
    byte[] cvcDescription = ArrayUtils.EMPTY_BYTE_ARRAY;
    byte[] privateKey = ArrayUtils.EMPTY_BYTE_ARRAY;
    List<byte[]> chainList = Arrays.asList(chain0, chain1);
    byte[][] chain = chainList.toArray(new byte[0][]);
    TerminalPermission terminalPermission = new TerminalPermission(SERVICE_PROVIDER);
    CertInChain certInChainPresent = new CertInChain(terminalPermission,
                                                     new CertInChainPK(terminalPermission.getRefID(), 0),
                                                     chain0);
    CertInChain certInChainOld = new CertInChain(terminalPermission,
                                                 new CertInChainPK(terminalPermission.getRefID(), 4),
                                                 ArrayUtils.EMPTY_BYTE_ARRAY);
    terminalPermission.setPendingRequest(pendingCertificateRequest);
    terminalPermission.getChain().add(certInChainPresent);
    terminalPermission.getChain().add(certInChainOld);
    Mockito.when(terminalPermissionRepository.findById(SERVICE_PROVIDER))
           .thenReturn(Optional.of(terminalPermission));

    terminalPermissionAOBean.storeCVCRequestCreated(SERVICE_PROVIDER,
                                                    "messageId",
                                                    request,
                                                    cvcDescription,
                                                    chain,
                                                    privateKey);
    Mockito.when(terminalPermissionRepository.findById(Mockito.anyString()))
           .thenReturn(Optional.of(terminalPermission));

    Assertions.assertEquals(2, terminalPermission.getChain().size());
    Assertions.assertTrue(terminalPermission.getChain().contains(certInChainPresent));
    Assertions.assertFalse(terminalPermission.getChain().contains(certInChainOld));
    Mockito.verify(pendingCertificateRequestRepository).saveAndFlush(pendingCertificateRequest);
    Mockito.verify(terminalPermissionRepository).saveAndFlush(terminalPermission);
    Mockito.verify(certInChainRepository, Mockito.times(2)).save(Mockito.any());
    Mockito.verify(certInChainRepository).delete(certInChainOld);
  }

  private byte[] getResourceAsByteArray(String path) throws Exception
  {
    try (InputStream resourceAsStream = TerminalPermissionAOBeanTest.class.getResourceAsStream(path))
    {
      return ByteStreams.toByteArray(resourceAsStream);
    }
  }

  @Test
  void addBlackListEntries()
  {
    BlackListEntryRepository blackListEntryRepository = Mockito.mock(BlackListEntryRepository.class);
    TerminalPermissionAOBean terminalPermissionAOBean = new TerminalPermissionAOBean(null, null, null, null,
                                                                                     blackListEntryRepository,
                                                                                     null, null, null, null);

    // Use Lock because of non-deterministic errors with parallelStream
    ReentrantLock reentrantLock = new ReentrantLock();
    List<BlackListEntry> mockedBlackListRepo = new ArrayList<>();
    Mockito.doAnswer(invocation -> {
      BlackListEntry blackListEntry = invocation.getArgument(0);
      reentrantLock.lock();
      mockedBlackListRepo.add(blackListEntry);
      reentrantLock.unlock();
      return null;
    }).when(blackListEntryRepository).save(Mockito.any());

    ByteArrayList specificIDList = new ByteArrayList();
    for ( int i = 0 ; i < 10000 ; i++ )
    {
      specificIDList.add(SERVICE_PROVIDER.concat(String.valueOf(i)).getBytes(StandardCharsets.UTF_8));
    }

    byte[] serviceProviderBytes = SERVICE_PROVIDER.getBytes(StandardCharsets.UTF_8);
    terminalPermissionAOBean.addBlackListEntries(serviceProviderBytes, specificIDList);
    Assertions.assertEquals(10000, mockedBlackListRepo.size());
    String serviceProviderBytesString = DatatypeConverter.printBase64Binary(serviceProviderBytes);
    for ( BlackListEntry entry : mockedBlackListRepo )
    {
      Assertions.assertEquals(serviceProviderBytesString, entry.getKey().getSectorID());
      Assertions.assertTrue(specificIDList.remove(DatatypeConverter.parseBase64Binary(entry.getKey()
                                                                                           .getSpecificID())));
    }
    Assertions.assertTrue(specificIDList.isEmpty());
  }

  @Test
  void testIsPublicClient() throws Exception
  {
    ConfigurationService configurationService = Mockito.mock(ConfigurationService.class);
    EidasMiddlewareConfig validConfiguration = ConfigurationTestHelper.createValidConfiguration();
    validConfiguration.getEidasConfiguration().setPublicServiceProviderName("sp-name");
    Mockito.when(configurationService.getConfiguration()).thenReturn(Optional.of(validConfiguration));
    TerminalPermissionAOBean terminalPermissionAOBean = new TerminalPermissionAOBean(null, null, null, null, null, null,
                                                                                     null, null, configurationService);
    //Correct name and cvcRefId
    Assertions.assertTrue(terminalPermissionAOBean.isPublicClient("cvcRefId"));

    //Wrong cvcRefId
    Assertions.assertFalse(terminalPermissionAOBean.isPublicClient("wrongCvcRefId"));

    //Wrong name
    validConfiguration.getEidasConfiguration().setPublicServiceProviderName("otherName");
    Assertions.assertFalse(terminalPermissionAOBean.isPublicClient("cvcRefId"));

    //No public SP in config
    validConfiguration.getEidasConfiguration().setPublicServiceProviderName(null);
    Assertions.assertFalse(terminalPermissionAOBean.isPublicClient("cvcRefId"));
  }
}

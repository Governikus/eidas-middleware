package de.governikus.eumw.poseidas.entities;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

import de.governikus.eumw.poseidas.server.idprovider.config.Configuration;
import de.governikus.eumw.poseidas.server.idprovider.config.Configuration_;
import de.governikus.eumw.poseidas.server.pki.entities.CVCUpdateLock;
import de.governikus.eumw.poseidas.server.pki.entities.CVCUpdateLock_;
import de.governikus.eumw.poseidas.server.pki.entities.CertInChain;
import de.governikus.eumw.poseidas.server.pki.entities.CertInChainPK;
import de.governikus.eumw.poseidas.server.pki.entities.CertInChain_;
import de.governikus.eumw.poseidas.server.pki.entities.ChangeKeyLock;
import de.governikus.eumw.poseidas.server.pki.entities.ChangeKeyLock_;
import de.governikus.eumw.poseidas.server.pki.entities.KeyArchive;
import de.governikus.eumw.poseidas.server.pki.entities.KeyArchive_;
import de.governikus.eumw.poseidas.server.pki.entities.PendingCertificateRequest;
import de.governikus.eumw.poseidas.server.pki.entities.PendingCertificateRequest_;
import de.governikus.eumw.poseidas.server.pki.entities.PendingCsr;
import de.governikus.eumw.poseidas.server.pki.entities.PendingCsr_;
import de.governikus.eumw.poseidas.server.pki.entities.RequestSignerCertificate;
import de.governikus.eumw.poseidas.server.pki.entities.RequestSignerCertificate_;
import de.governikus.eumw.poseidas.server.pki.entities.TerminalPermission;
import de.governikus.eumw.poseidas.server.pki.entities.TerminalPermission_;
import de.governikus.eumw.poseidas.server.pki.entities.TimerHistory;
import de.governikus.eumw.poseidas.server.pki.entities.TimerHistory_;


/**
 * Build the testsuite to test the equals and hashcode methods for entities.
 */
class EntitiesTests
{

  private static final String LOCKED_AT = "lockedAt";

  private static final String CVC = "cvc";

  private static final String STATUS = "status";

  private static final String PRIVATE_KEY = "privateKey";

  /**
   * Add a {@link EntityDescriptorI} to the entityDescriptors array to add test for an additional entity. <br>
   * If an entity needs special objects in its constructor the method
   * {@link EntityDescriptorI#getValueForClassExtension(String, boolean)} can be overridden. Otherwise, an
   * {@link IllegalArgumentException} will remind about this.
   */
  @TestFactory
  List<DynamicTest> testEntities()
  {
    List<EntityDescriptorI<?>> entityDescriptors = new ArrayList<>();

    // de.governikus.eumw.poseidas.server.pki.entities.CVCUpdateLock
    entityDescriptors.add(new EntityDescriptorI<CVCUpdateLock>()
    {

      @Override
      public Class<CVCUpdateLock> getEntityClass()
      {
        return CVCUpdateLock.class;
      }

      @Override
      public List<String> getFieldsRelevantForEquals()
      {

        return List.of(CVCUpdateLock_.TRUST_CENTER_URL);
      }

      @Override
      public List<String> getFieldNotRelevantForEquals()
      {
        return List.of(LOCKED_AT);
      }
    });

    // de.governikus.eumw.poseidas.server.pki.entities.PendingCsr
    entityDescriptors.add(new EntityDescriptorI<PendingCsr>()
    {

      @Override
      public Class<PendingCsr> getEntityClass()
      {
        return PendingCsr.class;
      }

      @Override
      public List<String> getFieldsRelevantForEquals()
      {
        return List.of(PendingCsr_.SP_ID);
      }

      @Override
      public List<String> getFieldNotRelevantForEquals()
      {
        return List.of("messageId", "notPollBefore");
      }
    });

    // de.governikus.eumw.poseidas.server.pki.entities.KeyArchive
    entityDescriptors.add(new EntityDescriptorI<KeyArchive>()
    {

      @Override
      public Class<KeyArchive> getEntityClass()
      {
        return KeyArchive.class;
      }

      @Override
      public List<String> getFieldsRelevantForEquals()
      {
        return List.of(KeyArchive_.KEY_NAME);
      }

      @Override
      public List<String> getFieldNotRelevantForEquals()
      {
        return List.of(CVC, PRIVATE_KEY);
      }

    });

    // de.governikus.eumw.poseidas.server.idprovider.config.Configuration
    entityDescriptors.add(new EntityDescriptorI<Configuration>()
    {

      @Override
      public Class<Configuration> getEntityClass()
      {
        return Configuration.class;
      }

      @Override
      public List<String> getFieldsRelevantForEquals()
      {
        return List.of(Configuration_.ID);
      }

      @Override
      public List<String> getFieldNotRelevantForEquals()
      {
        return List.of("xmlConfigBlob");
      }
    });

    // de.governikus.eumw.poseidas.server.pki.entities.ChangeKeyLock
    entityDescriptors.add(new EntityDescriptorI<ChangeKeyLock>()
    {

      @Override
      public Class<ChangeKeyLock> getEntityClass()
      {
        return ChangeKeyLock.class;
      }

      @Override
      public List<String> getFieldsRelevantForEquals()
      {
        return List.of(ChangeKeyLock_.KEY_NAME);
      }

      @Override
      public List<String> getFieldNotRelevantForEquals()
      {
        return List.of("autentIP", LOCKED_AT, "type");
      }
    });

    // de.governikus.eumw.poseidas.server.pki.entities.PendingCertificateRequest
    entityDescriptors.add(new EntityDescriptorI<PendingCertificateRequest>()
    {

      @Override
      public Class<PendingCertificateRequest> getEntityClass()
      {
        return PendingCertificateRequest.class;
      }

      @Override
      public List<String> getFieldsRelevantForEquals()
      {

        return List.of(PendingCertificateRequest_.REF_ID);
      }

      @Override
      public List<String> getFieldNotRelevantForEquals()
      {
        return List.of("requestData",
                       PRIVATE_KEY,
                       STATUS,
                       "additionalInfo",
                       "messageID",
                       "lastChanged",
                       "newCvcDescription",
                       "canBeSentAgain");
      }
    });

    // de.governikus.eumw.poseidas.server.pki.entities.RequestSignerCertificate
    entityDescriptors.add(new EntityDescriptorI<RequestSignerCertificate>()
    {

      @Override
      public Class<RequestSignerCertificate> getEntityClass()
      {
        return RequestSignerCertificate.class;
      }

      @Override
      public List<String> getFieldsRelevantForEquals()
      {

        return List.of(RequestSignerCertificate_.KEY);
      }

      @Override
      public List<String> getFieldNotRelevantForEquals()
      {
        return List.of(PRIVATE_KEY, "x509RequestSignerCertificate", STATUS);
      }

      @Override
      public Object getValueForClassExtension(String className, boolean firstValue)
      {
        return switch (className)
        {
          case "CertInChainPK" -> firstValue ? new CertInChainPK("ref-1", 1) : new CertInChainPK("ref-2", 2);

          default -> EntityDescriptorI.super.getValueForClassExtension(className, firstValue);
        };
      }
    });

    // de.governikus.eumw.poseidas.server.pki.entities.TerminalPermission
    entityDescriptors.add(new EntityDescriptorI<TerminalPermission>()
    {

      @Override
      public Class<TerminalPermission> getEntityClass()
      {
        return TerminalPermission.class;
      }

      @Override
      public List<String> getFieldsRelevantForEquals()
      {

        return List.of(TerminalPermission_.REF_ID);
      }

      @Override
      public List<String> getFieldNotRelevantForEquals()
      {
        return List.of("pendingRequest",
                       CVC,
                       "cvcDescription",
                       "cvcPrivateKey",
                       "riKey1",
                       "psKey",
                       "sectorID",
                       "notOnOrAfter",
                       "chain",
                       "masterList",
                       "masterListStoreDate",
                       "defectList",
                       "defectListStoreDate",
                       "blackListStoreDate",
                       "blackListVersion",
                       "rscChr",
                       "currentRequestSignerCertificate",
                       "pendingRequestSignerCertificate",
                       "nextCvcSequenceNumber",
                       "nextRscSequenceNumber",
                       "automaticCvcRenewFailed",
                       "automaticRscRenewFailed");
      }

      @Override
      public Object getValueForClassExtension(String className, boolean firstValue)
      {
        return switch (className)
        {
          case "PendingCertificateRequest" -> new PendingCertificateRequest(firstValue ? "ref1" : "ref2");
          case "RequestSignerCertificate" -> {
            RequestSignerCertificate cert = new RequestSignerCertificate();
            cert.setKey(new CertInChainPK(firstValue ? "ref1" : "ref2", firstValue ? 1 : 2));
            yield cert;
          }
          case "Set" -> new HashSet<>();
          default -> EntityDescriptorI.super.getValueForClassExtension(className, firstValue);
        };
      }
    });


    // de.governikus.eumw.poseidas.server.pki.entities.TimerHistory
    entityDescriptors.add(new EntityDescriptorI<TimerHistory>()
    {

      @Override
      public Class<TimerHistory> getEntityClass()
      {
        return TimerHistory.class;
      }

      @Override
      public List<String> getFieldsRelevantForEquals()
      {

        return List.of(TimerHistory_.ID);
      }

      @Override
      public List<String> getFieldNotRelevantForEquals()
      {
        return List.of("timerType", "message", "timestamp", "success");
      }
    });

    // de.governikus.eumw.poseidas.server.pki.entities.CertInChain
    entityDescriptors.add(new EntityDescriptorI<CertInChain>()
    {

      @Override
      public Class<CertInChain> getEntityClass()
      {
        return CertInChain.class;
      }

      @Override
      public List<String> getFieldsRelevantForEquals()
      {

        return List.of(CertInChain_.KEY);
      }

      @Override
      public List<String> getFieldNotRelevantForEquals()
      {
        return List.of("data", "terminalPermission");
      }

      @Override
      public Object getValueForClassExtension(String className, boolean firstValue)
      {
        return switch (className)
        {
          case "CertInChainPK" -> {
            CertInChainPK pk = new CertInChainPK();
            pk.setRefID(firstValue ? "A" : "B");
            pk.setPosInChain(firstValue ? 1 : 2);
            yield pk;
          }

          case "TerminalPermission" -> {
            TerminalPermission tp = new TerminalPermission();
            tp.setRefID(firstValue ? "TP1" : "TP2");
            yield tp;
          }
          default -> EntityDescriptorI.super.getValueForClassExtension(className, firstValue);
        };
      }
    });

    return entityDescriptors.stream()
                            .map(EntitiesEqualsAndHashcodeTestVerifier::new)
                            .map(EntitiesEqualsAndHashcodeTestVerifier::createDynamicTest)
                            .toList();
  }
}

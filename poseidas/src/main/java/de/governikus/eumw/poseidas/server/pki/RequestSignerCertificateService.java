package de.governikus.eumw.poseidas.server.pki;

import java.security.cert.X509Certificate;
import java.util.Optional;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cms.CMSTypedData;

import de.governikus.eumw.poseidas.server.pki.entities.RequestSignerCertificate;


/**
 * This interface is used to manage the {@link RequestSignerCertificate}.
 */
public interface RequestSignerCertificateService
{

  /**
   * Automatic RSC renewal is triggered this number of days before expiration.
   */
  int DEFAULT_DAYS_BEFORE_EXPIRATION = 21;

  /**
   * Generates a new {@link RequestSignerCertificateService} for the given entityId
   *
   * @param entityId entityId
   * @param lifespan Validity in months
   * @param rscChr CHR for private provider
   * @return {@link Optional#empty} if {@link RequestSignerCertificate} was created, otherwise an error message
   */
  Optional<String> generateNewPendingRequestSignerCertificate(String entityId, String rscChr, int lifespan);

  /**
   * Build a CMS container signed with the indicated RSC and containing the given data.
   * 
   * @param entityId entityId to indicate the RSC for signing
   * @param content content for the CMS container
   * @param contentType content type for the CMS container
   * @return {@link Optional} of CMS container, empty if signature not possible
   */
  Optional<byte[]> signCmsContainer(String entityId, CMSTypedData content, ASN1ObjectIdentifier contentType);

  /**
   * Gets the most recent request signer certificate for the given entityId
   *
   * @param entityId entityId
   * @return pending certificate if present, otherwise current certificate if present, otherwise <code>null</code>
   */
  X509Certificate getRequestSignerCertificate(String entityId);

  /**
   * Checks if a sp has a request signer certificate.
   *
   * @param entityId entityId
   * @return true if a pending or current request signer certificate is present. false otherwise.
   */
  boolean hasRequestSignerCertificate(String entityId);

  /**
   * Gets the current or pending request signer certificate for the given entityId
   *
   * @param entityId entityId
   * @param current <code>true</code> for current, <code>false</code> for pending
   * @return certificate if present, otherwise <code>null</code>
   */
  X509Certificate getRequestSignerCertificate(String entityId, boolean current);

  /**
   * Checks which terminals have request signer certificates due to expire and generates new certificates for these.
   */
  void renewOutdated();

  /**
   * Deletes the pending request certificate for a service provider
   *
   * @param entityId the entity ID of the service provider for which the pending RSC should be deleted
   * @return {@link Optional#empty} if the pending RSC was deleted, otherwise an error message
   */
  Optional<String> deletePendingRSC(String entityId);

  /**
   * Generates a new pending RSC and sends this RSC to the DVCA
   *
   * @param entityID the entity ID of the service provider for which the pending certificate should be sent to the DVCA
   * @return {@link Optional#empty} if the RSC was successfully sent to the DVCA, otherwise an error message
   */
  Optional<String> renewRSC(String entityID);

  /**
   * Sends a pending RSC to the DVCA
   *
   * @param entityID the entity ID of the service provider for which the pending certificate should be sent to the DVCA
   * @return {@link Optional#empty} if the RSC was successfully sent to the DVCA, otherwise an error message
   */
  Optional<String> sendPendingRSC(String entityID);
}

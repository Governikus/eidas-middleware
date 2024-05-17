/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.pki;

import java.io.IOException;
import java.security.SignatureException;

import de.governikus.eumw.poseidas.server.pki.entities.ChangeKeyLock;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import de.governikus.eumw.poseidas.cardbase.asn1.npa.ATConstants;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.CertificateDescription;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.CertificateHolderAuthorizationTemplate;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.ECCVCertificate;
import de.governikus.eumw.poseidas.cardserver.certrequest.CvcRequestGenerator;
import de.governikus.eumw.poseidas.cardserver.certrequest.CvcRequestGenerator.AdditionalCvcRequestInput;
import de.governikus.eumw.poseidas.cardserver.certrequest.CvcRequestGenerator.CvcRequestData;
import de.governikus.eumw.poseidas.cardserver.service.ServiceRegistry;
import de.governikus.eumw.poseidas.cardserver.service.hsm.HSMServiceFactory;
import de.governikus.eumw.poseidas.cardserver.service.hsm.impl.HSMException;
import de.governikus.eumw.poseidas.cardserver.service.hsm.impl.HSMService;
import lombok.Setter;


/**
 * Wrapper for generating a certificate request
 *
 * @author tautenhahn
 */
class PoseidasCertificateRequestGenerator
{

  private static final Log LOG = LogFactory.getLog(PoseidasCertificateRequestGenerator.class);

  private final TerminalPermissionAO facade;

  private final String entityID;

  private ECCVCertificate rootCVC;

  private ECCVCertificate oldCVC;

  private byte[] oldPrivKey;

  private CertificateDescription description;

  private AdditionalCvcRequestInput addData;

  @Setter
  private byte[] rscPrivateKey;

  @Setter
  private String rscAlias;

  private Integer nextCvcSequenceNumber;

  /**
   * Create instance for one-time use on behalf of specified service provider
   *
   * @param entityID
   */
  PoseidasCertificateRequestGenerator(String entityID, TerminalPermissionAO facade)
  {
    this.entityID = entityID;
    this.facade = facade;
  }

  private String createChr(String countryCode, String chrMnemonic, int sequenceNumber)
  {
    return countryCode + chrMnemonic + String.format("%05d", Math.max(1, sequenceNumber));
  }

  /**
   * Set the necessary data for a first request in case that you have received a CVCDescription corrected by the issuer.
   * In this case, you should skip the call of {@link #setIssuerForFirstRequest(String, String, byte[])} and
   * {@link #setDataForFirstRequest(String, boolean, boolean, String, String, String, int)}
   *
   * @param encodedRootCvc
   * @param encodedDescription
   * @param countryCode
   * @param chrMnemonic
   * @param sequenceNumber
   */
  void setDataForFirstRequest(byte[] encodedRootCvc,
                              byte[] encodedDescription,
                              String countryCode,
                              String chrMnemonic,
                              int sequenceNumber)
    throws IOException
  {
    rootCVC = new ECCVCertificate(encodedRootCvc);

    if (encodedDescription != null)
    {
      description = new CertificateDescription(encodedDescription);
    }
    CertificateHolderAuthorizationTemplate chat = new CertificateHolderAuthorizationTemplate(ATConstants.OID_AUTHENTICATION_TERMINALS,
                                                                                             new byte[ATConstants.VALUE_BYTE_COUNT]);

    addData = new AdditionalCvcRequestInput(createChr(countryCode, chrMnemonic, sequenceNumber), null, chat);
  }

  /**
   * Set the data needed for a subsequent request. All the data should be available from database.
   *
   * @param encodedRootCVC
   * @param encodedOldCVC
   * @param oldPrivateKey can be null if old private key is in the HSM
   * @param descriptionAsBytes
   * @param nextCvcSequenceNumber
   * @throws IOException
   */
  void prepareSubsequentRequest(byte[] encodedRootCVC,
                                byte[] encodedOldCVC,
                                byte[] oldPrivateKey,
                                byte[] descriptionAsBytes,
                                Integer nextCvcSequenceNumber)
    throws IOException
  {
    rootCVC = new ECCVCertificate(encodedRootCVC);
    oldCVC = new ECCVCertificate(encodedOldCVC);
    oldPrivKey = oldPrivateKey;
    this.nextCvcSequenceNumber = nextCvcSequenceNumber;
    if (descriptionAsBytes != null)
    {
      description = new CertificateDescription(descriptionAsBytes);
    }
  }



  /**
   * Create certificate request. As a side effect, the private key created in the process is stored within the HSM if
   * HSM connection is available.
   *
   * @return request and, if no HSM is available, private key
   * @throws IllegalArgumentException
   * @throws IOException
   * @throws SignatureException
   */
  CvcRequestData create() throws IOException, SignatureException
  {
    String newCHR = CvcRequestGenerator.generateNewCHR(oldCVC, addData, nextCvcSequenceNumber);
    boolean keyAlreadyThere = false;
    try
    {
      HSMService hsm = ServiceRegistry.Util.getServiceRegistry().getService(HSMServiceFactory.class).getHSMService();
      keyAlreadyThere = hsm.containsKey(newCHR) || (facade != null && facade.changeKeyLockExists(newCHR));
    }
    catch (HSMException e)
    {
      throw new IOException("HSM not available", e);
    }
    catch (UnsupportedOperationException e)
    {
      // in this case we assume key is not there (BOS simulator)
    }

    if (keyAlreadyThere)
    {
      return CvcRequestGenerator.generateRequest(oldCVC,
                                                 oldPrivKey,
                                                 rootCVC,
                                                 description,
                                                 addData,
                                                 true,
                                                 rscAlias,
                                                 rscPrivateKey,
                                                 nextCvcSequenceNumber);
    }

    ChangeKeyLock lock = null;
    if (facade != null)
    {
      lock = facade.obtainChangeKeyLock(newCHR, ChangeKeyLock.TYPE_DISTRIBUTE);
      if (lock == null)
      {
        LOG.debug(entityID + ": Key " + newCHR + " is currently being changed in the HSM cluster");
        throw new IllegalStateException("Key " + newCHR + " is currently being changed in the HSM cluster");
      }
      LOG.debug(entityID + ": lock for key " + newCHR + " obtained");
    }
    return CvcRequestGenerator.generateRequest(oldCVC,
                                               oldPrivKey,
                                               rootCVC,
                                               description,
                                               addData,
                                               false,
                                               rscAlias,
                                               rscPrivateKey,
                                               nextCvcSequenceNumber);
  }

  /**
   * return the certificate description
   */
  public byte[] getCertificateDescription()
  {
    return description.getEncoded();
  }
}

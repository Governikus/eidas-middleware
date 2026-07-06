/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardserver.certrequest;

import java.io.IOException;
import java.security.KeyPair;
import java.security.SignatureException;
import java.security.interfaces.ECPublicKey;

import org.apache.commons.lang3.ArrayUtils;

import de.governikus.autent.asn1.CVC;
import de.governikus.autent.asn1.CVCBody;
import de.governikus.autent.asn1.CVCRequest;
import de.governikus.autent.asn1.CertRequestReferenceInfos;
import de.governikus.eumw.poseidas.cardbase.AssertUtil;
import de.governikus.eumw.poseidas.cardserver.certrequest.CVCKeyPairBuilder.KeyDisposition;
import de.governikus.eumw.poseidas.cardserver.service.ServiceRegistry;
import de.governikus.eumw.poseidas.cardserver.service.hsm.HSMServiceFactory;
import de.governikus.eumw.poseidas.cardserver.service.hsm.impl.HSMService;
import de.governikus.eumw.poseidas.cardserver.service.hsm.impl.LocalCertAndKeyProvider;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;


/**
 * Generator for certificate requests.
 *
 * @author Jens Wothe, jw@bos-bremen.de
 * @author Arne Stahlbock, ast@bos-bremen.de
 */
@UtilityClass
@Slf4j
public class CvcRequestGenerator
{

  /**
   * Class for holding CVC request related data.
   */
  @RequiredArgsConstructor
  @Getter
  public static class CvcRequestData
  {

    private final byte[] certificateRequest;

    private final byte[] pkcs8PrivateKey;
  }

  /**
   * Generates new CHR by increasing old.
   *
   * @param oldCVC old CVC containing old CHR, <code>null</code> only permitted if additionalData containing CHR
   * @param nextCvcSequenceNumber
   * @return generated CHR or CHR from additionalData
   * @throws IOException
   * @throws IllegalArgumentException if additionalData not providing CHR and oldCVC <code>null</code>
   */
  public static String generateNewCHR(CVC oldCVC, Integer nextCvcSequenceNumber) throws IOException
  {

    if (oldCVC == null)
    {
      throw new IllegalArgumentException("old CVC not permitted as null if additionalData not containing CHR");
    }

    String oldCHR = null;
    try
    {
      oldCHR = oldCVC.getBody().getCertificateHolderReference();
    }
    catch (Exception e)
    {
      throw new IOException("Error in reading CHR from old certificate, possibly corrupted", e);
    }

    if (nextCvcSequenceNumber != null)
    {
      return changeNumberOfChr(oldCHR, nextCvcSequenceNumber);
    }
    return increaseCHR(oldCHR);
  }

  /**
   * Generates a request from given data.
   *
   * @param oldCVC used old CVC for creating new request, holder reference of CVC contains at last 5 bytes a sequence
   *          counter as alphanumeric ASCII characters to support increasing, <code>null</code> only permitted, if
   *          CertificateHolderReference and CertificateHolderAuthorizationTemplate given
   * @param oldPrivKey private key for signing the request, given as byte-array containing PKCS#8 structure,
   *          <code>null</code> permitted
   * @param rootCVC root CA CVC with ECC curve parameters, <code>null</code> not permitted
   * @param usePresentKey <code>true</code> to use key already in HSM, <code>false</code> to generate new
   * @param rscAlias alias of RSC to sign the request with, <code>null</code> to use old CVC for signing
   * @param rscPrivateKey key of RSC to sign the request with, only needed if no rscAlias given and no HSM used
   * @return request with key
   * @throws IllegalArgumentException when old CVC is <code>null</code> and additional data not given, sequence counter
   *           of used old CVC or additional data can not be increased correctly to create a certificate holder
   *           reference, root CA CVC <code>null</code> or no key can be generated for curve of CVC CA
   * @throws IOException
   * @throws SignatureException
   */
  public static CvcRequestData generateRequest(CVC oldCVC,
                                               byte[] oldPrivKey,
                                               CVC rootCVC,
                                               String newChr,
                                               boolean usePresentKey,
                                               String rscAlias,
                                               byte[] rscPrivateKey)
    throws IOException, SignatureException
  {
    // checks for required information
    AssertUtil.notNull(rootCVC, "root CVC CA");
    if (oldCVC == null)
    {
      AssertUtil.notNullOrEmpty(newChr, "CHR of additional data");
    }

    KeyDisposition keyDisposition = usePresentKey ? KeyDisposition.USE_PRESENT
      : oldCVC == null ? KeyDisposition.REPLACE : KeyDisposition.GENERATE_IF_NOT_PRESENT;

    KeyPair kp;
    try
    {
      kp = CVCKeyPairBuilder.getKeyPair(rootCVC, newChr, keyDisposition);
    }
    catch (Exception e)
    {
      throw new IOException("Cannot create key pair for new CVC", e);
    }

    CVCBody cvcBody = CVCBody.builder()
                             .profileIdentifier(0)
                             .holderReference(new CertRequestReferenceInfos(newChr))
                             .publicKeyOid(rootCVC.getBody().getPublicKey().getUsage())
                             .publicKey((ECPublicKey)kp.getPublic())
                             .build();

    HSMService hsm = ServiceRegistry.Util.getServiceRegistry().getService(HSMServiceFactory.class).getHSMService();
    byte[] innerSignature;
    try
    {
      innerSignature = hsm.sign(newChr, rootCVC.getBody().getPublicKey().getUsage(), cvcBody.getEncoded());
    }
    catch (Exception e)
    {
      throw new IOException("Cannot sign new CVC", e);
    }

    CVC cvcRequest = new CVC(cvcBody, innerSignature);

    byte[] requestBytes;
    if (rscAlias != null)
    {
      requestBytes = setOuterSignature(cvcRequest, rscAlias, rscPrivateKey);
    }
    else if (oldCVC == null)
    {
      requestBytes = cvcRequest.getEncoded();
    }
    else
    {
      String oldCHR = null;
      try
      {
        oldCHR = oldCVC.getBody().getCertificateHolderReference();
      }
      catch (Exception e)
      {
        throw new IOException("Error in reading CHR from old certificate, possibly corrupted", e);
      }
      requestBytes = setOuterSignature(cvcRequest, oldCHR, oldPrivKey);
    }

    return new CvcRequestData(requestBytes, kp.getPrivate() == null ? null : kp.getPrivate().getEncoded());
  }

  private static String changeNumberOfChr(String newCHR, int newNumber)
  {
    if (newCHR == null)
    {
      throw new IllegalArgumentException("newCHR must contain a value");
    }
    return String.format("%s%05d", newCHR.substring(0, newCHR.length() - 5), newNumber);
  }

  private static byte[] setOuterSignature(CVC requestCvc, String authorityReference, byte[] authorityReferenceKey)
    throws IOException, SignatureException
  {
    CVCRequest cvcRequest = CVCRequest.builder().cvc(requestCvc).authorityReference(authorityReference).build();
    byte[] outerSignatureData = ArrayUtils.addAll(requestCvc.getEncoded(),
                                                  cvcRequest.getAuthorityReference().getEncoded());

    if (authorityReferenceKey != null && authorityReferenceKey.length > 0)
    {
      LocalCertAndKeyProvider.getInstance().addKey(authorityReference, authorityReferenceKey);
    }


    HSMService hsm = ServiceRegistry.Util.getServiceRegistry().getService(HSMServiceFactory.class).getHSMService();

    byte[] outerSignature;
    try
    {
      outerSignature = hsm.sign(authorityReference, requestCvc.getBody().getPublicKey().getUsage(), outerSignatureData);
    }
    catch (

    Exception e)
    {
      throw new IOException("Cannot sign new CVC", e);
    }

    cvcRequest.setOuterSignature(outerSignature);

    return cvcRequest.getEncoded();
  }

  /**
   * Produces a new CHR by increasing the counter of an old CHR if possible.
   *
   * @param oldCHR old CHR of which the counter is to be increased
   * @return {@link String} representation of new CHR
   */
  public static String increaseCHR(String oldCHR)
  {
    String identifier = oldCHR.substring(0, oldCHR.length() - 5);
    String counter = oldCHR.substring(oldCHR.length() - 5);
    return identifier + increase(counter, counter.length() - 1);
  }

  /**
   * Helper method for increasing a String.
   *
   * @param str the String to be increased
   * @param position the position of the character to be increased
   * @return the increased String
   */
  private static String increase(String str, int position)
  {
    // overflow for DPCom, note this could be different for other customers
    if ("99999".equals(str))
    {
      return "00001";
    }

    int index = COUNTER_CHARSET.indexOf(str.charAt(position));
    if (str.length() == 1)
    {
      if (index > 0)
      {
        return COUNTER_CHARSET.substring(index - 1, index);
      }
      else
      {
        return COUNTER_CHARSET.substring(COUNTER_CHARSET.length() - 1);
      }
    }

    if (index > 0)
    {
      return str.substring(0, str.length() - 1) + COUNTER_CHARSET.substring(index - 1, index);
    }
    else
    {
      return increase(str.substring(0, str.length() - 1), position - 1)
             + COUNTER_CHARSET.substring(COUNTER_CHARSET.length() - 1);
    }
  }

  /**
   * Character set to be used in counters. Note: this is the set conform to DPCom policy, other customers could be
   * different!
   */
  private static final String COUNTER_CHARSET = "9876543210";


}

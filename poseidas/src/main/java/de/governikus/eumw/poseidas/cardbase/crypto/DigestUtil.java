/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardbase.crypto;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import de.governikus.eumw.poseidas.cardbase.AssertUtil;
import de.governikus.eumw.poseidas.cardbase.asn1.OID;
import de.governikus.eumw.poseidas.cardbase.constants.OIDConstants;
import lombok.experimental.UtilityClass;


@UtilityClass
public final class DigestUtil
{

  /**
   * Gets {@link MessageDigest} instance by OID.
   *
   * @param oid OID of signature algorithm or hash algorithm, <code>null</code> not permitted
   * @return appropriate {@link MessageDigest} instance, if available
   * @throws IllegalArgumentException if given OID <code>null</code> or unknown
   * @throws NoSuchAlgorithmException if algorithm unknown
   * @see OIDConstants
   * @see #getSHA1Digest(OID)
   * @see #getSHA224Digest(OID)
   * @see #getSHA256Digest(OID)
   * @see #getSHA384Digest(OID)
   * @see #getSHA512Digest(OID)
   */
  public static MessageDigest getDigestByOID(OID oid) throws NoSuchAlgorithmException
  {
    AssertUtil.notNull(oid, "OID");

    MessageDigest md = getSHA1Digest(oid);
    if (md != null)
    {
      return md;
    }
    md = getSHA224Digest(oid);
    if (md != null)
    {
      return md;
    }
    md = getSHA256Digest(oid);
    if (md != null)
    {
      return md;
    }
    md = getSHA384Digest(oid);
    if (md != null)
    {
      return md;
    }
    md = getSHA512Digest(oid);
    if (md != null)
    {
      return md;
    }
    throw new IllegalArgumentException("unknown OID");
  }

  /**
   * Gets MessageDigest in case use of SHA1 indicated in OID.
   *
   * @param oid oid
   * @return MessageDigest, <code>null</code> for SHA1 not used
   * @throws NoSuchAlgorithmException if MessageDigest can not be instantiated
   * @see HashAlgorithmEnum#SHA1
   */
  private static MessageDigest getSHA1Digest(OID oid) throws NoSuchAlgorithmException
  {
    MessageDigest md = null;
    if (oid.equals(OIDConstants.OID_TA_ECDSA_SHA_1) || oid.equals(OIDConstants.OID_TA_RSA_PSS_SHA_1)
        || oid.equals(OIDConstants.OID_TA_RSA_V1_5_SHA_1) || oid.equals(OIDConstants.OID_RI_ECDH_SHA_1)
        || oid.equals(OIDConstants.OID_RI_DH_SHA_1) || oid.equals(HashAlgorithmEnum.SHA1.getOID()))
    {
      md = MessageDigest.getInstance("SHA-1");
    }
    return md;
  }

  /**
   * Gets MessageDigest in case use of SHA224 indicated in OID.
   *
   * @param oid oid
   * @return MessageDigest, <code>null</code> for SHA224 not used
   * @throws NoSuchAlgorithmException if MessageDigest can not be instantiated
   * @see HashAlgorithmEnum#SHA224
   */
  private static MessageDigest getSHA224Digest(OID oid) throws NoSuchAlgorithmException
  {
    MessageDigest md = null;
    if (oid.equals(OIDConstants.OID_TA_ECDSA_SHA_224) || oid.equals(OIDConstants.OID_RI_ECDH_SHA_224)
        || oid.equals(OIDConstants.OID_RI_DH_SHA_224) || oid.equals(HashAlgorithmEnum.SHA224.getOID()))
    {
      md = MessageDigest.getInstance("SHA-224");
    }
    return md;
  }

  /**
   * Gets MessageDigest in case use of SHA256 indicated in OID.
   *
   * @param oid oid
   * @return MessageDigest, <code>null</code> for SHA256 not used
   * @throws NoSuchAlgorithmException if MessageDigest can not be instantiated
   * @see HashAlgorithmEnum#SHA256
   */
  private static MessageDigest getSHA256Digest(OID oid) throws NoSuchAlgorithmException
  {
    MessageDigest md = null;
    if (oid.equals(OIDConstants.OID_TA_ECDSA_SHA_256) || oid.equals(OIDConstants.OID_TA_RSA_PSS_SHA_256)
        || oid.equals(OIDConstants.OID_TA_RSA_V1_5_SHA_256) || oid.equals(OIDConstants.OID_RI_ECDH_SHA_256)
        || oid.equals(OIDConstants.OID_RI_DH_SHA_256) || oid.equals(OIDConstants.OID_PSA_ECDH_ECSCHNORR_SHA256)
        || oid.equals(OIDConstants.OID_PSC_ECDH_ECSCHNORR_SHA256)
        || oid.equals(OIDConstants.OID_PSM_ECDH_ECSCHNORR_SHA256) || oid.equals(HashAlgorithmEnum.SHA256.getOID()))
    {
      md = MessageDigest.getInstance("SHA-256");
    }
    return md;
  }

  /**
   * Gets MessageDigest in case use of SHA384 indicated in OID.
   *
   * @param oid oid
   * @return MessageDigest, <code>null</code> for SHA384 not used
   * @throws NoSuchAlgorithmException if MessageDigest can not be instantiated
   * @see HashAlgorithmEnum#SHA384
   */
  private static MessageDigest getSHA384Digest(OID oid) throws NoSuchAlgorithmException
  {
    MessageDigest md = null;
    if (oid.equals(HashAlgorithmEnum.SHA384.getOID()) || oid.equals(OIDConstants.OID_TA_ECDSA_SHA_384)
        || oid.equals(OIDConstants.OID_RI_ECDH_SHA_384) || oid.equals(OIDConstants.OID_RI_DH_SHA_384)
        || oid.equals(OIDConstants.OID_PSA_ECDH_ECSCHNORR_SHA384)
        || oid.equals(OIDConstants.OID_PSC_ECDH_ECSCHNORR_SHA384)
        || oid.equals(OIDConstants.OID_PSM_ECDH_ECSCHNORR_SHA384))
    {
      md = MessageDigest.getInstance("SHA-384");
    }
    return md;
  }

  /**
   * Gets MessageDigest in case use of SHA512 indicated in OID.
   *
   * @param oid oid
   * @return MessageDigest, <code>null</code> for SHA512 not used
   * @throws NoSuchAlgorithmException if MessageDigest can not be instantiated
   * @see HashAlgorithmEnum#SHA512
   */
  private static MessageDigest getSHA512Digest(OID oid) throws NoSuchAlgorithmException
  {
    MessageDigest md = null;
    if (oid.equals(HashAlgorithmEnum.SHA512.getOID()) || oid.equals(OIDConstants.OID_TA_ECDSA_SHA_512)
        || oid.equals(OIDConstants.OID_TA_RSA_PSS_SHA_512) || oid.equals(OIDConstants.OID_TA_RSA_V1_5_SHA_512)
        || oid.equals(OIDConstants.OID_RI_ECDH_SHA_512) || oid.equals(OIDConstants.OID_RI_DH_SHA_512)
        || oid.equals(OIDConstants.OID_PSA_ECDH_ECSCHNORR_SHA512)
        || oid.equals(OIDConstants.OID_PSC_ECDH_ECSCHNORR_SHA512)
        || oid.equals(OIDConstants.OID_PSM_ECDH_ECSCHNORR_SHA512))
    {
      md = MessageDigest.getInstance("SHA-512");
    }
    return md;
  }
}

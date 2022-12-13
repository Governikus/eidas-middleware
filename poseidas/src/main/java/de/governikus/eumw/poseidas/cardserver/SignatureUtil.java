/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardserver;

import java.security.NoSuchAlgorithmException;
import java.security.Signature;

import de.governikus.eumw.poseidas.cardbase.asn1.OID;
import de.governikus.eumw.poseidas.cardbase.constants.OIDConstants;
import de.governikus.eumw.utils.key.SecurityProvider;


public class SignatureUtil
{

  private SignatureUtil()
  {
    super();
  }

  /**
   * Creates Signature instance according to given OID.
   *
   * @param oid OID, <code>null</code> not permitted
   * @return Signature instance
   * @throws IllegalArgumentException if OID <code>null</code> or unknown
   * @throws NoSuchAlgorithmException if algorithm not supported
   */
  public static Signature createSignature(OID oid) throws NoSuchAlgorithmException
  {
    Signature sig = null;
    if (oid == null)
    {
      throw new IllegalArgumentException("null not permitted");
    }
    if (oid.equals(OIDConstants.OID_TA_ECDSA_SHA_1))
    {
      sig = Signature.getInstance("SHA1withCVC-ECDSA", SecurityProvider.BOUNCY_CASTLE_PROVIDER);
    }
    else if (oid.equals(OIDConstants.OID_TA_ECDSA_SHA_224))
    {
      sig = Signature.getInstance("SHA224withCVC-ECDSA", SecurityProvider.BOUNCY_CASTLE_PROVIDER);
    }
    else if (oid.equals(OIDConstants.OID_TA_ECDSA_SHA_256))
    {
      sig = Signature.getInstance("SHA256withCVC-ECDSA", SecurityProvider.BOUNCY_CASTLE_PROVIDER);
    }
    else if (oid.equals(OIDConstants.OID_TA_ECDSA_SHA_384))
    {
      sig = Signature.getInstance("SHA384withCVC-ECDSA", SecurityProvider.BOUNCY_CASTLE_PROVIDER);
    }
    else if (oid.equals(OIDConstants.OID_TA_ECDSA_SHA_512))
    {
      sig = Signature.getInstance("SHA512withCVC-ECDSA", SecurityProvider.BOUNCY_CASTLE_PROVIDER);
    }
    else if (oid.equals(OIDConstants.OID_TA_RSA_PSS_SHA_1))
    {
      sig = Signature.getInstance("SHA1withRSA/PSS", SecurityProvider.BOUNCY_CASTLE_PROVIDER);
    }
    else if (oid.equals(OIDConstants.OID_TA_RSA_PSS_SHA_256))
    {
      sig = Signature.getInstance("SHA256withRSA/PSS", SecurityProvider.BOUNCY_CASTLE_PROVIDER);
    }
    else if (oid.equals(OIDConstants.OID_TA_RSA_PSS_SHA_512))
    {
      sig = Signature.getInstance("SHA512withRSA/PSS", SecurityProvider.BOUNCY_CASTLE_PROVIDER);
    }
    else if (oid.equals(OIDConstants.OID_TA_RSA_V1_5_SHA_1))
    {
      sig = Signature.getInstance("SHA1withRSA", SecurityProvider.BOUNCY_CASTLE_PROVIDER);
    }
    else if (oid.equals(OIDConstants.OID_TA_RSA_V1_5_SHA_256))
    {
      sig = Signature.getInstance("SHA256withRSA", SecurityProvider.BOUNCY_CASTLE_PROVIDER);
    }
    else if (oid.equals(OIDConstants.OID_TA_RSA_V1_5_SHA_512))
    {
      sig = Signature.getInstance("SHA512withRSA", SecurityProvider.BOUNCY_CASTLE_PROVIDER);
    }
    else
    {
      throw new IllegalArgumentException("unknown OID");
    }
    return sig;
  }
}

/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardbase.crypto.ec;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPublicKey;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import de.governikus.eumw.poseidas.cardbase.AssertUtil;
import de.governikus.eumw.poseidas.cardserver.SignatureUtil;
import lombok.experimental.UtilityClass;


/**
 * Implementation of some EC calculations.
 */
@UtilityClass
public final class ECMath
{

  /**
   * Verifies EC signature.
   *
   * @param signature raw signature, no ASN.1 structure, <code>null</code> or empty not permitted
   * @param signedData data which was signed, <code>null</code> not permitted
   * @param pubKey public key of signer, <code>null</code> not permitted
   * @param oid {@link ASN1ObjectIdentifier} used in signing, <code>null</code> not permitted, must be a valid
   *          {@link ASN1ObjectIdentifier}
   * @return <code>true</code> in case of signature verified successfully, <code>false</code> otherwise
   * @throws IllegalArgumentException if any argument <code>null</code> or signature empty
   * @throws NoSuchAlgorithmException if given digest algorithm unknown
   */
  public static boolean verifySignature(byte[] signature,
                                        byte[] signedData,
                                        ECPublicKey pubKey,
                                        ASN1ObjectIdentifier oid)
    throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, IllegalArgumentException
  {
    AssertUtil.notNullOrEmpty(signature, "signature");
    AssertUtil.notNull(signedData, "signed data");
    AssertUtil.notNull(pubKey, "public key");
    AssertUtil.notNull(oid, "oid");

    Signature sig = SignatureUtil.createSignature(oid);
    sig.initVerify(pubKey);
    sig.update(signedData);

    return sig.verify(signature);
  }
}

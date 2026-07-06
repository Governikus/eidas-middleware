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
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.spec.ECParameterSpec;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.eac.ECDSAPublicKey;

import de.governikus.autent.asn1.CVC;
import de.governikus.autent.asn1.OIDConstants;
import de.governikus.autent.asn1.utils.PublicKeyUtils;
import de.governikus.eumw.poseidas.cardbase.AssertUtil;
import de.governikus.eumw.poseidas.cardserver.service.ServiceRegistry;
import de.governikus.eumw.poseidas.cardserver.service.hsm.HSMServiceFactory;
import de.governikus.eumw.poseidas.cardserver.service.hsm.impl.HSMException;
import de.governikus.eumw.poseidas.cardserver.service.hsm.impl.HSMService;

import lombok.extern.slf4j.Slf4j;


/**
 * Supports creation of key pairs suitable for CVCs. Note: such a key pair differs from those used only as ephemeral
 * keys, e.g. by the private key being stored in the HSM.
 *
 * @author Arne Stahlbock, ast@bos-bremen.de
 */
@Slf4j
public class CVCKeyPairBuilder
{

  // Lifespan of key pair in month
  public static final int LIFESPAN = 2;

  /**
   * Dispositions for HSM keys.
   * <p>
   * Copyright: Copyright (c) 2013
   * </p>
   * <p>
   * Company: bremen online services GmbH und Co. KG
   * </p>
   *
   * @author Arne Stahlbock, ast@bos-bremen.de
   */
  enum KeyDisposition
  {
    /**
     * Generate new key at any rate.
     */
    REPLACE,
    /**
     * Do not generate new key even if requested key is not present.
     */
    USE_PRESENT,
    /**
     * If a key is present, use that, otherwise generate new.
     */
    GENERATE_IF_NOT_PRESENT
  }

  /**
   * Creates a key pair for use with CVCs.
   *
   * @param cert CVC to retrieve domain parameters and algorithms from, <code>null</code> not permitted
   * @param alias alias for key, <code>null</code> or empty not permitted
   * @param disposition key disposition, <code>null</code> not permitted
   * @return key pair, private key of which should be <code>null</code> in most cases
   * @throws IllegalArgumentException if any argument <code>null</code> or empty
   * @throws IOException
   * @throws InvalidAlgorithmParameterException
   * @throws NoSuchAlgorithmException
   * @throws NoSuchProviderException
   * @throws HSMException
   * @throws IllegalStateException
   */
  static KeyPair getKeyPair(CVC cert, String alias, KeyDisposition disposition) throws IOException, HSMException,
    NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, CertificateException
  {
    AssertUtil.notNull(cert, "CVC");
    AssertUtil.notNullOrEmpty(alias, "key alias");
    AssertUtil.notNull(disposition, "key disposition");

    String algorithm;
    ECParameterSpec spec;
    ECDSAPublicKey baseKey = (ECDSAPublicKey)cert.getBody().getPublicKey();
    ASN1ObjectIdentifier oid = cert.getBody().getPublicKey().getUsage();
    if (oid.equals(OIDConstants.OID_TA_ECDSA_SHA_1) || oid.equals(OIDConstants.OID_TA_ECDSA_SHA_224)
        || oid.equals(OIDConstants.OID_TA_ECDSA_SHA_256) || oid.equals(OIDConstants.OID_TA_ECDSA_SHA_384)
        || oid.equals(OIDConstants.OID_TA_ECDSA_SHA_512))
    {
      spec = PublicKeyUtils.extractParametersFromPublicKey(baseKey);
      algorithm = "EC";
    }
    else
    {
      throw new UnsupportedOperationException("other algorithms not supported at this time");
    }

    HSMService hsm = ServiceRegistry.Util.getServiceRegistry().getService(HSMServiceFactory.class).getHSMService();

    try
    {
      if (disposition == KeyDisposition.USE_PRESENT
          || (disposition == KeyDisposition.GENERATE_IF_NOT_PRESENT && hsm.containsKey(alias)))
      {
        return new KeyPair(hsm.getPublicKey(alias), null);
      }
    }
    catch (UnsupportedOperationException e)
    {
      if (log.isDebugEnabled())
      {
        log.debug("Unable to retrieve public key.", e);
      }
      // BOS simulator is unable to retrieve public key, therefore generate new
      KeyPair kp = hsm.generateKeyPair(algorithm, spec, alias, null, true, LIFESPAN);
      return new KeyPair(kp.getPublic(), kp.getPrivate());
    }

    if (disposition == KeyDisposition.REPLACE)
    {
      KeyPair kp = hsm.generateKeyPair(algorithm, spec, alias, null, true, LIFESPAN);
      return new KeyPair(kp.getPublic(), kp.getPrivate());
    }
    KeyPair kp = hsm.generateKeyPair(algorithm, spec, alias, null, false, LIFESPAN);
    return new KeyPair(kp.getPublic(), kp.getPrivate());
  }
}

/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardserver.eac.ta;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

import de.governikus.eumw.poseidas.cardbase.AssertUtil;
import de.governikus.eumw.poseidas.cardbase.ByteUtil;
import de.governikus.eumw.poseidas.cardbase.asn1.OID;
import de.governikus.eumw.poseidas.cardserver.service.ServiceRegistry;
import de.governikus.eumw.poseidas.cardserver.service.hsm.HSMServiceFactory;
import de.governikus.eumw.poseidas.cardserver.service.hsm.impl.HSMException;
import de.governikus.eumw.poseidas.cardserver.service.hsm.impl.HSMService;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;


/**
 * Class for executing the Terminal Authentication protocol as part of Extended Access Control.
 *
 * @author Arne Stahlbock, ast@bos-bremen.de
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class TerminalAuthentication
{

  /**
   * Generates the signature for Terminal Authentication.
   *
   * @param alias alias of key for signing, <code>null</code> not permitted
   * @param algorithm OID of signature algorithm, <code>null</code> not permitted
   * @param idPicc ID of PICC, <code>null</code> not permitted
   * @param rPicc challenge, <code>null</code> not permitted
   * @param compOwnEphPubKey compressed ephemeral public key, <code>null</code> not permitted
   * @param auxiliaryData auxiliary data, may be <code>null</code>
   * @return signature
   * @throws IllegalArgumentException if any argument (except auxiliaryData) <code>null</code>
   * @throws InvalidKeySpecException
   * @throws NoSuchAlgorithmException
   * @throws NoSuchProviderException
   * @throws InvalidKeyException
   * @throws SignatureException
   * @throws IOException
   * @throws CertificateException
   * @throws KeyStoreException
   * @throws UnrecoverableKeyException
   */
  public static byte[] sign(String alias,
                            OID algorithm,
                            byte[] idPicc,
                            byte[] rPicc,
                            byte[] compOwnEphPubKey,
                            byte[] auxiliaryData)
    throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException,
    SignatureException, IOException, UnrecoverableKeyException, KeyStoreException, CertificateException,
    HSMException
  {
    AssertUtil.notNullOrEmpty(alias, "alias of key");
    AssertUtil.notNull(algorithm, "OID of algorithm");
    AssertUtil.notNullOrEmpty(idPicc, "idPicc");
    AssertUtil.notNullOrEmpty(rPicc, "rPicc");
    AssertUtil.notNullOrEmpty(compOwnEphPubKey, "compressed own public key");

    byte[] completeChallenge = ByteUtil.combine(new byte[][]{idPicc, rPicc, compOwnEphPubKey, auxiliaryData});
    HSMService hsm = ServiceRegistry.Util.getServiceRegistry()
                                         .getService(HSMServiceFactory.class)
                                         .getHSMService();

    return hsm.sign(alias, algorithm, completeChallenge);
  }
}

/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardserver.eac.ca;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import javax.crypto.SecretKey;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import de.governikus.eumw.poseidas.cardbase.AssertUtil;
import de.governikus.eumw.poseidas.cardbase.ByteUtil;
import de.governikus.eumw.poseidas.cardbase.Hex;
import de.governikus.eumw.poseidas.cardbase.asn1.OID;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.si.ChipAuthenticationDomainParameterInfo;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.si.ChipAuthenticationInfo;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.si.ChipAuthenticationPublicKeyInfo;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.si.PACEInfo;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.si.SubjectPublicKeyInfo;
import de.governikus.eumw.poseidas.cardbase.constants.OIDConstants;
import de.governikus.eumw.poseidas.cardbase.crypto.CipherUtil;
import de.governikus.eumw.poseidas.cardbase.crypto.ec.ECUtil;
import de.governikus.eumw.poseidas.cardbase.crypto.kdf.KeyDerivationHandler;
import de.governikus.eumw.poseidas.cardbase.crypto.kdf.KeyDerivationHandlerFactory;
import de.governikus.eumw.poseidas.cardbase.crypto.key.KeyHandler;
import de.governikus.eumw.poseidas.cardbase.npa.InfoSelector.ChipAuthenticationData;
import de.governikus.eumw.poseidas.cardserver.eac.crypto.impl.KeyHandlerEC;
import de.governikus.eumw.poseidas.cardserver.eac.protocol.InvalidEidException;


/**
 * Class for executing Chip Authentication as part of Extended Access Control.
 *
 * @author Arne Stahlbock, ast@bos-bremen.de
 */
public class ChipAuthentication
{

  /**
   * Reference to the {@link Log}.
   */
  private static final Log LOG = LogFactory.getLog(ChipAuthentication.class);

  /**
   * Version.
   */
  private final int caVersion;

  /**
   * Reference to the {@link OID} of the specific CA subprotocol to be used.
   */
  private final OID oid;

  /**
   * Reference to the {@link ChipAuthenticationDomainParameterInfo}.
   */
  private final ChipAuthenticationDomainParameterInfo caDomParamInfo;

  /**
   * Reference to the {@link ChipAuthenticationPublicKeyInfo}.
   */
  private final ChipAuthenticationPublicKeyInfo caPubKeyInfo;

  /**
   * Reference to the (previously used) PACEInfo.
   */
  private final PACEInfo paceInfo;

  /**
   * Reference to the handler for key derivation operations.
   */
  private KeyDerivationHandler kdh = null;

  /**
   * Reference to the handler for key operations.
   */
  private KeyHandler kh = null;

  /**
   * Reference to the MAC key established during CA run.
   */
  private SecretKey macKey = null;

  /**
   * Reference to the encryption key established during CA run.
   */
  private SecretKey encKey = null;

  /**
   * Flag indicating whether CA has been successfully executed.
   */
  private boolean success = false;


  /**
   * Constructor.
   *
   * @param caInfo {@link ChipAuthenticationInfo}, <code>null</code> not permitted
   * @param caDomParamInfo {@link ChipAuthenticationDomainParameterInfo}, <code>null</code> not permitted
   * @param caPubKeyInfo {@link ChipAuthenticationPublicKeyInfo}, <code>null</code> permitted for CA version 3
   * @param paceInfo {@link PACEInfo} or previously executed PACE, <code>null</code> permitted
   * @throws IllegalArgumentException if any argument <code>null</code>
   * @throws NoSuchAlgorithmException
   * @throws IOException
   */
  public ChipAuthentication(ChipAuthenticationData caData,
                            ChipAuthenticationPublicKeyInfo caPubKeyInfo,
                            PACEInfo paceInfo)
    throws IOException, NoSuchAlgorithmException
  {
    super();
    if (caData == null)
    {
      throw new IllegalArgumentException("null not permitted");
    }

    try
    {
      this.caVersion = caData.getCaInfo().getVersion();
    }
    catch (IOException e)
    {
      throw new IllegalArgumentException("Unable to construct CA: cannot read version", e);
    }
    if (this.caVersion < 1 || this.caVersion > 3)
    {
      throw new IllegalArgumentException("Unable to construct CA: unknown version");
    }

    if (caPubKeyInfo == null && this.caVersion != 3)
    {
      throw new IllegalArgumentException("null not permitted for caPubKeyInfo when CA version 1 or 2 used");
    }

    this.oid = caData.getCaInfo().getProtocol();
    this.caDomParamInfo = caData.getCaDomParamInfo();
    this.caPubKeyInfo = caPubKeyInfo;
    this.paceInfo = paceInfo;
    this.initCA();
  }

  /**
   * Initializes instance by constructing the appropriate handlers.
   *
   * @throws IllegalArgumentException if unsupported protocol detected
   * @throws IOException
   * @throws NoSuchAlgorithmException
   */
  private void initCA() throws IOException, NoSuchAlgorithmException
  {
    LOG.debug("Initializing CA version " + this.caVersion + " for protocol " + this.oid);
    if (this.oid.equals(OIDConstants.OID_CA_ECDH_AES_CBC_CMAC_128))
    {
      this.kdh = KeyDerivationHandlerFactory.newKeyDerivationHandler("AES", 128);
      this.kh = new KeyHandlerEC(ECUtil.parameterSpecFromDomainParameters(this.caDomParamInfo)
                                       .getCurve()
                                       .getField()
                                       .getFieldSize()
                                 / 8);
    }
    else if (this.oid.equals(OIDConstants.OID_CA_ECDH_AES_CBC_CMAC_192))
    {
      this.kdh = KeyDerivationHandlerFactory.newKeyDerivationHandler("AES", 192);
      this.kh = new KeyHandlerEC(ECUtil.parameterSpecFromDomainParameters(this.caDomParamInfo)
                                       .getCurve()
                                       .getField()
                                       .getFieldSize()
                                 / 8);
    }
    else if (this.oid.equals(OIDConstants.OID_CA_ECDH_AES_CBC_CMAC_256))
    {
      this.kdh = KeyDerivationHandlerFactory.newKeyDerivationHandler("AES", 256);
      this.kh = new KeyHandlerEC(ECUtil.parameterSpecFromDomainParameters(this.caDomParamInfo)
                                       .getCurve()
                                       .getField()
                                       .getFieldSize()
                                 / 8);
    }
    else
    {
      throw new IllegalArgumentException("unsupported protocol for CA");
    }
  }

  /**
   * Processes final response from card (CA version 2).
   *
   * @param tacaKeyPair key pair, <code>null</code> not permitted
   * @param nonce nonce, <code>null</code> or empty not permitted
   * @param authToken authentication token, <code>null</code> or empty not permitted
   * @return
   * @throws IOException
   * @throws InvalidKeyException
   * @throws IllegalArgumentException if any parameter <code>null</code> or empty
   * @throws NoSuchAlgorithmException
   * @throws NoSuchProviderException
   * @throws InvalidKeySpecException
   * @throws InvalidEidException
   */
  public boolean processResponse(KeyPair tacaKeyPair, byte[] nonce, byte[] authToken)
    throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException,
    InvalidKeySpecException, InvalidEidException
  {
    AssertUtil.notNull(tacaKeyPair, "key pair");
    AssertUtil.notNullOrEmpty(nonce, "nonce");
    AssertUtil.notNullOrEmpty(authToken, "authentication token");
    return this.processCA2Response(tacaKeyPair, nonce, authToken);
  }

  /**
   * Processes final response from card.
   *
   * @param tacaKeyPair key pair, <code>null</code> not permitted
   * @param nonce nonce, must be non-null and non-empty for CA version 2
   * @param authToken authentication token, must be non-null and non-empty for CA version 2
   * @param cardKeyBytes public key of card, must be non-null and non-empty for CA version 3
   * @return
   * @throws IOException
   * @throws InvalidKeyException
   * @throws IllegalArgumentException if any parameter <code>null</code> or empty
   * @throws NoSuchAlgorithmException
   * @throws NoSuchProviderException
   * @throws InvalidKeySpecException
   * @throws InvalidEidException
   */
  private boolean processCA2Response(KeyPair tacaKeyPair, byte[] nonce, byte[] authToken)
    throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException,
    InvalidKeySpecException, InvalidEidException
  {
    byte[] cardKeyBytes;
    if (this.caVersion == 2 && nonce != null && nonce.length > 0 && authToken != null && authToken.length > 0)
    {
      SubjectPublicKeyInfo keyInfo = this.caPubKeyInfo.getChipAuthenticationPublicKey();
      // remove leading zero is ok here for current card generation, may be different for future cards
      cardKeyBytes = ByteUtil.removeLeadingZero(keyInfo.getSubjectPublicKey().getValue());
    }
    else
    {
      throw new IllegalArgumentException("given set of parameters not matching requirements");
    }

    LOG.debug("Public key of PICC: " + Hex.hexify(cardKeyBytes));
    PublicKey chipKey = null;
    try
    {
      chipKey = this.kh.buildKeyFromBytes(this.caDomParamInfo, cardKeyBytes);
    }
    catch (IllegalArgumentException e)
    {
      throw new InvalidEidException(e);
    }
    byte[] sharedBytes = this.kh.calculateSharedSecret(tacaKeyPair.getPrivate(), chipKey);
    LOG.debug("Private key of server: " + Hex.hexify(tacaKeyPair.getPrivate().getEncoded()));
    LOG.debug("Shared secret: " + Hex.hexify(sharedBytes));

    this.encKey = this.kdh.deriveEncKey(sharedBytes, nonce);
    this.macKey = this.kdh.deriveMACKey(sharedBytes, nonce);
    LOG.debug("Derived Encryption key: " + Hex.hexify(this.encKey.getEncoded()));
    LOG.debug("Derived MAC key: " + Hex.hexify(this.macKey.getEncoded()));

    int paceVersion = 2;
    if (this.paceInfo != null)
    {
      paceVersion = this.paceInfo.getVersion();
    }

    byte[] structure = this.kh.convertPublicKey(tacaKeyPair.getPublic(), this.oid, paceVersion == 1);
    byte[] mac = CipherUtil.cMAC(structure, macKey, CipherUtil.AES_CMAC_DEFAULT_LENGTH);
    if (!Arrays.equals(authToken, mac))
    {
      LOG.debug("CA not successful: could not verify MAC");
      this.success = false;
    }
    else
    {
      LOG.debug("CA successful: MAC ok");
      this.success = true;
    }
    return this.success;
  }

  /**
   * Gets MAC key established during CA, required for subsequent Secure Messaging.
   *
   * @return MAC key
   * @throws IllegalStateException if CA has not been successfully executed yet
   */
  public synchronized SecretKey getMacKey()
  {
    if (!this.success)
    {
      throw new IllegalStateException("CA not yet successfully executed");
    }
    return this.macKey;
  }

  /**
   * Gets encryption key established during CA, required for subsequent Secure Messaging.
   *
   * @return encryption key
   * @throws IllegalStateException if CA has not been successfully executed yet
   */
  public synchronized SecretKey getEncKey()
  {
    if (!this.success)
    {
      throw new IllegalStateException("CA not yet successfully executed");
    }
    return this.encKey;
  }
}

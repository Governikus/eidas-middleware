/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardserver.eac.protocol;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import de.governikus.eumw.poseidas.cardbase.AssertUtil;
import de.governikus.eumw.poseidas.cardbase.Hex;
import de.governikus.eumw.poseidas.cardbase.asn1.OID;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.AuthenticationTerminals;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.CertificateHolderAuthorizationTemplate;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.ECCVCPath;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.ECCVCertificate;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.SecurityInfos;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.si.ChipAuthenticationDomainParameterInfo;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.si.ChipAuthenticationInfo;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.si.ChipAuthenticationPublicKeyInfo;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.si.PACEInfo;
import de.governikus.eumw.poseidas.cardbase.constants.OIDConstants;
import de.governikus.eumw.poseidas.cardbase.crypto.ec.ECUtil;
import de.governikus.eumw.poseidas.cardbase.crypto.key.KeyHandler;
import de.governikus.eumw.poseidas.cardbase.crypto.sm.AESKeyMaterial;
import de.governikus.eumw.poseidas.cardbase.npa.InfoSelector;
import de.governikus.eumw.poseidas.cardbase.npa.InfoSelector.ChipAuthenticationData;
import de.governikus.eumw.poseidas.cardbase.npa.NPAUtil;
import de.governikus.eumw.poseidas.cardserver.eac.ca.ChipAuthentication;
import de.governikus.eumw.poseidas.cardserver.eac.crypto.SignedDataChecker;
import de.governikus.eumw.poseidas.cardserver.eac.crypto.impl.KeyHandlerEC;
import de.governikus.eumw.poseidas.cardserver.eac.ta.CertAndKeyProvider;
import de.governikus.eumw.poseidas.cardserver.eac.ta.TerminalAuthentication;
import de.governikus.eumw.poseidas.cardserver.service.hsm.impl.HSMException;
import de.governikus.eumw.poseidas.cardserver.service.hsm.impl.LocalCertAndKeyProvider;
import de.governikus.eumw.poseidas.cardserver.sm.AESBatchSecureMessaging;
import de.governikus.eumw.poseidas.cardserver.sm.BatchAESEncSSCIvParameterSpec;
import de.governikus.eumw.poseidas.cardserver.sm.BatchSecureMessaging;
import de.governikus.eumw.poseidas.ecardcore.model.EAC1InputTypeWrapper;
import de.governikus.eumw.poseidas.ecardcore.model.EAC1OutputTypeWrapper;
import de.governikus.eumw.poseidas.ecardcore.model.EAC2InputTypeWrapper;
import de.governikus.eumw.poseidas.ecardcore.model.EAC2OutputTypeWrapper;
import iso.std.iso_iec._24727.tech.schema.DIDAuthenticationDataType;
import iso.std.iso_iec._24727.tech.schema.EAC1InputType;
import iso.std.iso_iec._24727.tech.schema.EAC1OutputType;
import iso.std.iso_iec._24727.tech.schema.EAC2InputType;
import iso.std.iso_iec._24727.tech.schema.EAC2OutputType;
import iso.std.iso_iec._24727.tech.schema.EACAdditionalInputType;


/**
 * This class performs the server part of EAC in a distributed setting.
 *
 * @author Arne Stahlbock, ast@bos-bremen.de
 */
public class EACServer
{

  private static final Log LOG = LogFactory.getLog(EACServer.class);

  /**
   * Constant for OID of EAC2 protocol.
   */
  public static final String PROTOCOL_EAC2 = "urn:oid:1.3.162.15480.3.0.14.2";

  /**
   * Constant indicating first server step: input to TACA is to be computed with card output from PACE.
   */
  public static final int STEP_PACE_OUTPUT_TO_TACA_INPUT = 1;

  /**
   * Constant indicating final server step: evaluate card output from complete TACA.
   */
  public static final int STEP_TACA_RESULT = 3;

  /**
   * Reference to the {@link ChipAuthenticationData} selected when creating second input.
   */
  private ChipAuthenticationData caData = null;

  /**
   * Reference to the {@link PACEInfo} selected when creating second input.
   */
  private PACEInfo paceInfo = null;

  /**
   * Reference to the ephemeral key pair for TA/CA.
   */
  private KeyPair ephemeralTACAKeys = null;

  /**
   * Reference to the {@link SecurityInfos} read from EF.CardAccess.
   */
  private SecurityInfos efCardAccess = null;

  /**
   * Constructor.
   */
  public EACServer()
  {
    super();
  }

  /**
   * Produces input for TACA.
   *
   * @param firstOutput {@link EAC1OutputType} from PACE, <code>null</code> not permitted
   * @param additionalParameters additional data: array of two or three elements required, first must be
   *          {@link EAC1InputType}, second {@link CertAndKeyProvider}, third element ( {@link Boolean})
   * @return {@link EAC2InputType} for TACA
   * @throws IllegalArgumentException if firstOutput <code>null</code> or additionalParameters not matching
   *           requirement
   * @throws IOException
   * @throws InvalidAlgorithmParameterException
   * @throws NoSuchAlgorithmException
   * @throws NoSuchProviderException
   * @throws InvalidKeyException
   * @throws InvalidKeySpecException
   * @throws SignatureException
   */
  private EAC2InputTypeWrapper produceSecondInput(EAC1OutputTypeWrapper firstOutput,
                                                  Object[] additionalParameters)
    throws IOException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException,
    InvalidKeyException, InvalidKeySpecException, SignatureException, UnrecoverableKeyException, KeyStoreException,
    CertificateException, HSMException, InvalidEidException
  {
    AssertUtil.notNull(firstOutput, "first output");
    AssertUtil.notNullOrEmpty(additionalParameters, "additional parameters");
    if (additionalParameters.length != 2)
    {
      throw new IllegalArgumentException("three parameters required as additional input");
    }
    AssertUtil.notNull(additionalParameters[0], "instance of EAC1InputType");
    AssertUtil.notNull(additionalParameters[1], "instance of CertAndKeyProvider");
    if (!(additionalParameters[0] instanceof EAC1InputTypeWrapper))
    {
      throw new IllegalArgumentException("parameter is not instance of EAC1InputType");
    }
    if (!(additionalParameters[1] instanceof CertAndKeyProvider))
    {
      throw new IllegalArgumentException("parameter is not instance of CertAndKeyProvider");
    }
    EAC1InputTypeWrapper firstInput = (EAC1InputTypeWrapper)additionalParameters[0];
    ECCVCertificate termCert = findTermCert(firstInput.getCertificateList());
    if (termCert == null)
    {
      throw new IllegalArgumentException("EAC1InputType not containing required data");
    }

    CertAndKeyProvider cakProvider = (CertAndKeyProvider)additionalParameters[1];
    this.efCardAccess = new SecurityInfos();
    this.efCardAccess.decode(firstOutput.getEFCardAccess());

    List<ChipAuthenticationInfo> caInfoList = this.efCardAccess.getChipAuthenticationInfo();
    List<ChipAuthenticationDomainParameterInfo> caDomParamList = this.efCardAccess.getChipAuthenticationDomainParameterInfo();
    List<PACEInfo> paceInfoList = this.efCardAccess.getPACEInfo();
    AssertUtil.notNullOrEmpty(caInfoList, "list of CA info");
    AssertUtil.notNullOrEmpty(caDomParamList, "list of CA domain parameters");
    AssertUtil.notNullOrEmpty(paceInfoList, "list of PACE info");

    this.caData = InfoSelector.selectCAData(caInfoList, caDomParamList);
    if (this.caData == null)
    {
      throw new InvalidEidException("no acceptable chip authentication domain parameters found");
    }

    this.paceInfo = InfoSelector.selectPACEInfo(paceInfoList);
    OID protocol = this.caData.getCaDomParamInfo().getProtocol();
    KeyHandler kh = null;
    if (protocol.equals(OIDConstants.OID_CA_ECDH))
    {
      kh = new KeyHandlerEC(ECUtil.parameterSpecFromDomainParameters(this.caData.getCaDomParamInfo())
                                  .getCurve()
                                  .getField()
                                  .getFieldSize()
                            / 8);
    }
    else
    {
      throw new IllegalArgumentException("not supported protocol '" + protocol + "' , supported: "
                                         + OIDConstants.OID_CA_ECDH);
    }

    // generate key pair
    this.ephemeralTACAKeys = kh.generateKeyPair(this.caData.getCaDomParamInfo());
    LOG.debug("Generated key pair, public part: "
              + Hex.hexify(this.ephemeralTACAKeys.getPublic().getEncoded()));
    byte[] compressedKey = kh.compressKey(this.ephemeralTACAKeys.getPublic());
    byte[] ephemeralPublicKey = kh.ephemeralKeyBytes(this.ephemeralTACAKeys.getPublic());

    List<byte[]> cl = new ArrayList<>();

    String termHolder = new String(termCert.getChildElementByPath(ECCVCPath.HOLDER_REFERENCE).getValue(),
                                   StandardCharsets.UTF_8);
    for ( String car : firstOutput.getCertificationAuthorityReference() )
    {
      List<byte[]> certList = cakProvider.getCertChain(car, termHolder);
      if (certList != null && !certList.isEmpty())
      {
        cl = certList;
        break;
      }
    }
    if (cl.isEmpty() && !firstOutput.getCertificationAuthorityReference().isEmpty())
    {
      // certificate chain not available but requested
      return null;
    }

    byte[] signatureKey = cakProvider.getKeyByHolder(termHolder);
    if (signatureKey != null)
    {
      LocalCertAndKeyProvider.getInstance().addKey(termHolder, signatureKey);
    }

    EAC2InputTypeWrapper result2 = new EAC2InputTypeWrapper();
    result2.setProtocol(PROTOCOL_EAC2);
    result2.setEphemeralPublicKey(ephemeralPublicKey);
    result2.setCertificateList(cl);

    // sign if possible
    byte[] rPicc = firstOutput.getChallenge();
    if (rPicc != null)
    {
      byte[] idPicc = firstOutput.getIDPICC();
      byte[] convertedSignature = produceSignature(termCert,
                                                   firstInput.getAuthenticatedAuxiliaryData(),
                                                   idPicc,
                                                   rPicc,
                                                   compressedKey);
      result2.setSignature(convertedSignature);
    }

    return result2;
  }

  /**
   * Produces signature for TA.
   *
   * @param termCert terminal certificate
   * @param auxiliaryData auxiliary data
   * @param idPicc ID of PICC received from PACE
   * @param rPicc challenge
   * @return signature as byte-array
   * @throws HSMException
   * @throws IOException
   * @throws CertificateException
   * @throws KeyStoreException
   * @throws SignatureException
   * @throws NoSuchProviderException
   * @throws NoSuchAlgorithmException
   * @throws InvalidKeySpecException
   * @throws IllegalArgumentException
   * @throws UnrecoverableKeyException
   * @throws InvalidKeyException
   */
  private static byte[] produceSignature(ECCVCertificate termCert,
                                         byte[] auxiliaryData,
                                         byte[] idPicc,
                                         byte[] rPicc,
                                         byte[] compressedKey)
    throws InvalidKeyException, UnrecoverableKeyException, InvalidKeySpecException, NoSuchAlgorithmException,
    NoSuchProviderException, SignatureException, KeyStoreException, CertificateException, IOException,
    HSMException
  {
    AssertUtil.notNull(termCert, "terminal certificate");
    AssertUtil.notNullOrEmpty(idPicc, "ID of PICC");
    AssertUtil.notNullOrEmpty(rPicc, "challenge");

    OID signatureAlg = (OID)termCert.getChildElementByPath(ECCVCPath.PUBLIC_KEY_OID);
    String termHolder = new String(termCert.getChildElementByPath(ECCVCPath.HOLDER_REFERENCE).getValue(),
                                   StandardCharsets.UTF_8);

    // create signature
    return TerminalAuthentication.sign(termHolder, signatureAlg, idPicc, rPicc, compressedKey, auxiliaryData);
  }

  /**
   * Processes output from complete TACA.
   *
   * @param secondOutput {@link EAC2OutputType} from TACA, <code>null</code> not permitted
   * @param additionalParameters additional data: array of one element required - {@link SignedDataChecker}
   * @return {@link EACFinal} object holding relevant data for following procedures outside of EAC
   * @throws IllegalArgumentException if secondOutput <code>null</code> or additionalParameters not matching
   *           requirement
   * @throws IOException
   * @throws NoSuchAlgorithmException
   * @throws NoSuchPaddingException
   * @throws InvalidKeyException
   * @throws NoSuchProviderException
   * @throws InvalidKeySpecException
   * @throws SignatureException
   * @throws BadPaddingException
   * @throws IllegalBlockSizeException
   * @throws InvalidEidException
   */
  private EACFinal processCompleteTACAOutput(EAC2OutputTypeWrapper secondOutput,
                                             Object[] additionalParameters)
    throws IOException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException,
    InvalidKeySpecException, InvalidEidException
  {
    AssertUtil.notNull(secondOutput, "second output");
    AssertUtil.notNullOrEmpty(additionalParameters, "additional parameters");
    if (additionalParameters.length != 1)
    {
      throw new IllegalArgumentException("exactly one parameter required as instance of SignedDataChecker");
    }
    AssertUtil.notNull(additionalParameters[0], "instance of SignedDataChecker");
    if (!(additionalParameters[0] instanceof SignedDataChecker))
    {
      throw new IllegalArgumentException("parameter is not instance of SignedDataChecker");
    }
    SignedDataChecker checker = (SignedDataChecker)additionalParameters[0];
    byte[] cardSecurityBytes = secondOutput.getEFCardSecurity();
    AssertUtil.notNull(cardSecurityBytes, "EF.CardSecurity from card");

    byte[] nonce = secondOutput.getNonce();
    byte[] authToken = secondOutput.getAuthenticationToken();
    byte[] cardKeyBytes = secondOutput.getEphemeralPublicKey();
    if (this.caData.getCaInfo().getVersion() == 3)
    {
      AssertUtil.notNull(cardKeyBytes, "ephemeral public key");
    }
    else
    {
      AssertUtil.notNull(nonce, "nonce from card");
      AssertUtil.notNull(authToken, "authentication token from card");
    }

    // check signature on EF.CardSecurity
    Certificate signerCert = checker.checkSignedData(cardSecurityBytes);
    if (signerCert == null)
    {
      throw new InvalidEidException("signature on EF.CardSecurity could not be verified");
    }
    SecurityInfos cardSecurity = NPAUtil.fromCardSecurityBytes(cardSecurityBytes);
    if (!matchSecurityInfos(this.efCardAccess, cardSecurity, extractSerialNumber(signerCert)))
    {
      throw new InvalidEidException("contents of EF.CardSecurity and EF.CardAccess do not match");
    }

    ChipAuthenticationPublicKeyInfo caPubKeyInfo = null;
    if (this.caData.getCaInfo().getVersion() != 3)
    {
      List<ChipAuthenticationPublicKeyInfo> caPubKeyInfoList = cardSecurity.getChipAuthenticationPublicKeyInfo();
      if (caPubKeyInfoList == null || caPubKeyInfoList.isEmpty())
      {
        throw new IllegalArgumentException("Required data for CA not available in EF.CardSecurity");
      }
      caPubKeyInfo = InfoSelector.selectCAPubKeyInfo(caPubKeyInfoList, this.caData.getCaInfo());
    }
    ChipAuthentication ca = new ChipAuthentication(this.caData, caPubKeyInfo, this.paceInfo);

    boolean success;
    if (this.caData.getCaInfo().getVersion() == 3)
    {
      success = ca.processResponse(this.ephemeralTACAKeys, cardKeyBytes);
    }
    else
    {
      success = ca.processResponse(this.ephemeralTACAKeys, nonce, authToken);
    }

    if (success)
    {
      SecretKey macKey = ca.getMacKey();
      SecretKey encKey = ca.getEncKey();
      BatchSecureMessaging sm = null;
      if (macKey.getAlgorithm().equals("AES"))
      {
        BatchAESEncSSCIvParameterSpec ssc = new BatchAESEncSSCIvParameterSpec(new byte[16], encKey);
        AESKeyMaterial smKeyMaterial = new AESKeyMaterial(encKey, macKey, ssc);
        sm = new AESBatchSecureMessaging(smKeyMaterial);
      }
      return new EACFinal(sm, cardSecurityBytes, this.caData, cardKeyBytes);
    }
    return null;
  }

  /**
   * Executes one server-side step of EAC protocol.
   *
   * @param <P> type of next input to client or final result of EAC
   * @param <Q> type of result from client
   * @param stepSelect step to perform, only {@link #STEP_PACE_OUTPUT_TO_TACA_INPUT}, {@link #STEP_OPTIONAL}
   *          or {@link #STEP_TACA_RESULT} accepted
   * @param resultClass class of result from client, for {@link #STEP_PACE_OUTPUT_TO_TACA_INPUT}
   *          {@link EAC1OutputType} required, for {@link #STEP_OPTIONAL} {@link EAC2OutputType}, for
   *          {@link #STEP_TACA_RESULT} {@link EAC2OutputType}
   * @param result result from client, <code>null</code> not permitted
   * @param parameterClass class of next input to client or final result of EAC, for
   *          {@link #STEP_PACE_OUTPUT_TO_TACA_INPUT} {@link EAC2InputType} required, for
   *          {@link #STEP_OPTIONAL} {@link EACAdditionalInputType}, for {@link #STEP_TACA_RESULT}
   *          {@link EACFinal}
   * @param additionalParameters additional input data, for {@link #STEP_PACE_OUTPUT_TO_TACA_INPUT} array of
   *          three elements required: first must be {@link EAC1InputType}, second {@link CertAndKeyProvider},
   *          third element ({@link Boolean}); for {@link #STEP_OPTIONAL} array of two elements required:
   *          first must be {@link EAC1InputType}, second {@link EAC1OutputType}; for
   *          {@link #STEP_TACA_RESULT} array of one element required: {@link SignedDataChecker}
   * @return next input to client or final result of EAC
   * @throws IllegalArgumentException if unknown step selected, if resultClass / parameterClass not matching
   *           selected step, if result <code>null</code>, if additionalParameters not matching requirement of
   *           selected step
   * @throws InternalError if anything during production of step output fails
   */
  public <P extends Object, Q extends DIDAuthenticationDataType> P executeStep(int stepSelect,
                                                                               Class<Q> resultClass,
                                                                               Q result,
                                                                               Class<P> parameterClass,
                                                                               Object[] additionalParameters)
    throws InvalidEidException
  {
    if (stepSelect == STEP_PACE_OUTPUT_TO_TACA_INPUT)
    {
      if (resultClass != EAC1OutputTypeWrapper.class)
      {
        throw new IllegalArgumentException("incorrect result class for given step");
      }
      if (parameterClass != EAC2InputTypeWrapper.class)
      {
        throw new IllegalArgumentException("incorrect parameter class for given step");
      }
      try
      {
        return parameterClass.cast(this.produceSecondInput((EAC1OutputTypeWrapper)result,
                                                           additionalParameters));
      }
      catch (IllegalArgumentException | InvalidEidException e)
      {
        throw e;
      }
      catch (Exception e)
      {
        throw new RuntimeException("internal error: " + e.getMessage(), e);
      }
    }

    if (stepSelect == STEP_TACA_RESULT)
    {
      if (resultClass != EAC2OutputTypeWrapper.class)
      {
        throw new IllegalArgumentException("incorrect result class for given step");
      }
      if (parameterClass != EACFinal.class)
      {
        throw new IllegalArgumentException("incorrect parameter class for given step");
      }
      try
      {
        return parameterClass.cast(this.processCompleteTACAOutput((EAC2OutputTypeWrapper)result,
                                                                  additionalParameters));
      }
      catch (IllegalArgumentException | InvalidEidException e)
      {
        throw e;
      }
      catch (Exception e)
      {
        throw new RuntimeException("internal error: " + e.getMessage(), e);
      }
    }

    throw new IllegalArgumentException("unknown/unsupported step");
  }

  /**
   * Finds a terminal certificate in a given certificate list.
   *
   * @param certList list of certificates, <code>null</code> not permitted
   * @return found terminal certificate, <code>null</code> if none present, first if more than one present
   * @throws IOException
   */
  private static ECCVCertificate findTermCert(List<byte[]> certList) throws IOException
  {
    AssertUtil.notNull(certList, "certificate list");
    for ( byte[] certBytes : certList )
    {
      AssertUtil.notNullOrEmpty(certBytes, "bytes of certificate (input for PACE)");
      ECCVCertificate testCert = new ECCVCertificate(certBytes);
      CertificateHolderAuthorizationTemplate chat = testCert.getChat();
      if (chat.getAccessRoleAndRights()
              .isRole(AuthenticationTerminals.AccessRoleEnum.AUTHENTICATION_TERMINAL))
      {
        return testCert;
      }
    }
    return null;
  }

  /**
   * Checks if {@link SecurityInfos} contained in EF.CardAccess match with those contained in EF.CardSecurity.
   *
   * @param efCardAccess
   * @param efCardSecurity
   * @return result of check
   */
  private static boolean matchSecurityInfos(SecurityInfos efCardAccess,
                                            SecurityInfos efCardSecurity,
                                            Integer serialNumber)
  {
    if (efCardSecurity.getPACEInfo() == null
        || !efCardSecurity.getPACEInfo().containsAll(efCardAccess.getPACEInfo()))
    {
      return false;
    }

    if (efCardAccess.getPACEDomainParameterInfo() != null
        && (efCardSecurity.getPACEDomainParameterInfo() == null
            || !efCardSecurity.getPACEDomainParameterInfo()
                              .containsAll(efCardAccess.getPACEDomainParameterInfo())))
    {
      return false;
    }

    // ID cards signed by document signers with serial number 106 and below have a defect according to
    // TR-03127 section D, run full check only on others
    if (serialNumber == null || serialNumber > 106)
    {
      if (efCardAccess.getChipAuthenticationInfo() != null
          && (efCardSecurity.getChipAuthenticationInfo() == null
              || !efCardSecurity.getChipAuthenticationInfo()
                                .containsAll(efCardAccess.getChipAuthenticationInfo())))
      {
        return false;
      }

      if (efCardAccess.getChipAuthenticationDomainParameterInfo() != null
          && (efCardSecurity.getChipAuthenticationDomainParameterInfo() == null
              || !efCardSecurity.getChipAuthenticationDomainParameterInfo()
                                .containsAll(efCardAccess.getChipAuthenticationDomainParameterInfo())))
      {
        return false;
      }
    }
    // run reduced check on defect cards: compare only first ChipAuthenticationInfo and
    // ChipAuthenticationDomainParameterInfo
    else
    {
      if (efCardAccess.getChipAuthenticationInfo() != null
          && (efCardSecurity.getChipAuthenticationInfo() == null
              || !efCardSecurity.getChipAuthenticationInfo()
                                .contains(efCardAccess.getChipAuthenticationInfo().get(0))))
      {
        return false;
      }

      if (efCardAccess.getChipAuthenticationDomainParameterInfo() != null
          && (efCardSecurity.getChipAuthenticationDomainParameterInfo() == null
              || !efCardSecurity.getChipAuthenticationDomainParameterInfo()
                                .contains(efCardAccess.getChipAuthenticationDomainParameterInfo().get(0))))
      {
        return false;
      }
    }

    return efCardAccess.getTerminalAuthenticationInfo() == null
           || efCardSecurity.getTerminalAuthenticationInfo() != null
              && efCardSecurity.getTerminalAuthenticationInfo()
                               .containsAll(efCardAccess.getTerminalAuthenticationInfo());
  }

  private static Integer extractSerialNumber(Certificate signerCert)
  {
    // attention: we use the serial number from the DN, not the usual one
    // the spec does not say anything about this but the one from the DN fits better
    try
    {
      org.bouncycastle.asn1.x509.Certificate certStructure = org.bouncycastle.asn1.x509.Certificate.getInstance(signerCert.getEncoded());
      return Integer.valueOf(certStructure.getSubject()
                                          .getRDNs(new ASN1ObjectIdentifier("2.5.4.5"))[0].getFirst()
                                                                                          .getValue()
                                                                                          .toString());
    }
    catch (Exception e)
    {
      return null;
    }
  }
}

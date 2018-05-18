/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardserver.eac.functions.ps;

import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.util.ArrayList;
import java.util.List;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import de.governikus.eumw.poseidas.cardbase.AssertUtil;
import de.governikus.eumw.poseidas.cardbase.ByteUtil;
import de.governikus.eumw.poseidas.cardbase.Hex;
import de.governikus.eumw.poseidas.cardbase.asn1.ASN1;
import de.governikus.eumw.poseidas.cardbase.asn1.ASN1Constants;
import de.governikus.eumw.poseidas.cardbase.asn1.OID;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.si.AlgorithmIdentifier;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.si.PSAInfo;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.si.PSCInfo;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.si.PSInfo;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.si.PSPublicKeyInfo;
import de.governikus.eumw.poseidas.cardbase.card.SmartCardCodeConstants;
import de.governikus.eumw.poseidas.cardbase.crypto.DigestUtil;
import de.governikus.eumw.poseidas.cardbase.crypto.ec.ECMath;
import de.governikus.eumw.poseidas.cardbase.crypto.ec.ECUtil;
import de.governikus.eumw.poseidas.cardserver.EACServerUtil;
import de.governikus.eumw.poseidas.cardserver.eac.functions.FunctionStep;
import de.governikus.eumw.poseidas.cardserver.eac.functions.TransmitCommandCreator;
import de.governikus.eumw.poseidas.cardserver.eac.functions.TransmitResultEvaluator;
import de.governikus.eumw.poseidas.cardserver.eac.functions.impl.AbstractFunctionStep;
import de.governikus.eumw.poseidas.cardserver.eac.functions.transmitAPDU.TransmitAPDU;
import de.governikus.eumw.poseidas.cardserver.eac.functions.transmitAPDU.TransmitAPDUParameter;
import de.governikus.eumw.poseidas.cardserver.eac.functions.transmitAPDU.TransmitAPDUResult;
import iso.std.iso_iec._24727.tech.schema.InputAPDUInfoType;
import iso.std.iso_iec._24727.tech.schema.Transmit;
import iso.std.iso_iec._24727.tech.schema.TransmitResponse;


public class PseudonymousSignature extends
  AbstractFunctionStep<PseudonymousSignatureParameter, PseudonymousSignatureResult> implements
  FunctionStep<PseudonymousSignatureParameter, PseudonymousSignatureResult>,
  TransmitCommandCreator<PseudonymousSignatureParameter>,
  TransmitResultEvaluator<PseudonymousSignatureResult>
{

  /**
   * Tag for sending sector public key to card.
   */
  private static final String SECTOR_PUBLIC_KEY_TAG = "80";

  /**
   * Tag for sending signature input to card.
   */
  private static final String INPUT_TAG = "81";

  /**
   * Tag for first sector specific ID received from card.
   */
  private static final byte[] FIRST_PSEUDONYM_KEY_TAG = new byte[]{(byte)0x82};

  /**
   * Tag for second sector specific ID received from card.
   */
  private static final byte[] SECOND_PSEUDONYM_KEY_TAG = new byte[]{(byte)0x83};

  /**
   * Tag for second sector specific ID received from card.
   */
  private static final byte[] PSEUDONYMOUS_SIGNATURE_TAG = new byte[]{(byte)0x84};


  public PseudonymousSignature(TransmitAPDU transmit)
  {
    super(transmit);
  }

  @Override
  public int getMinimumCount()
  {
    return 2;
  }

  @Override
  public int getMaximumCount()
  {
    return 2;
  }

  @Override
  public PseudonymousSignatureResult evaluate(TransmitAPDUResult transmitResult, int[] responseIndices)
  {
    responseIndices = TransmitResultEvaluator.Util.checkArguments(transmitResult,
                                                                  responseIndices,
                                                                  getMinimumCount(),
                                                                  getMaximumCount());
    if (transmitResult.getThrowable() != null)
    {
      return new PseudonymousSignatureResult(transmitResult.getThrowable());
    }

    PseudonymousSignatureResult psResult = new PseudonymousSignatureResult();
    try
    {
      for ( int i : responseIndices )
      {
        ResponseAPDU r = new ResponseAPDU(transmitResult.getData().getOutputAPDU().get(i));
        if (r.getSW() != SmartCardCodeConstants.SUCCESSFULLY_PROCESSED)
        {
          return new PseudonymousSignatureResult(
                                                 new IllegalStateException(
                                                                           "pseudonymous signature not performed"));
        }
        byte[] data = r.getData();
        if (data == null || data.length == 0)
        {
          continue;
        }
        ASN1 resASN1 = new ASN1(data);
        ASN1[] sigData = resASN1.getChildElementsByDTagBytes(FIRST_PSEUDONYM_KEY_TAG);
        if (sigData != null && sigData.length == 1)
        {
          psResult.setFirstKey(sigData[0].getValue());
        }
        sigData = resASN1.getChildElementsByDTagBytes(SECOND_PSEUDONYM_KEY_TAG);
        if (sigData != null && sigData.length == 1)
        {
          psResult.setSecondKey(sigData[0].getValue());
        }
        sigData = resASN1.getChildElementsByDTagBytes(PSEUDONYMOUS_SIGNATURE_TAG);
        if (sigData != null && sigData.length == 1)
        {
          psResult.setSignature(sigData[0].getValue());
        }
      }
    }
    catch (Exception e)
    {
      return new PseudonymousSignatureResult(e);
    }
    if (psResult.getSignature() == null)
    {
      return new PseudonymousSignatureResult(
                                             new IllegalStateException("pseudonymous signature not performed"));
    }
    return psResult;
  }

  @Override
  public List<InputAPDUInfoType> create(PseudonymousSignatureParameter parameter) throws Exception
  {
    return create(parameter, null);
  }

  @Override
  public List<InputAPDUInfoType> create(PseudonymousSignatureParameter parameter,
                                        List<ResponseAPDU> acceptedResponseList) throws IOException
  {
    List<InputAPDUInfoType> tcList = new ArrayList<>();

    PSInfo psInfo = parameter.getPsInfo();
    String dataFieldString = EACServerUtil.makeTag(EACServerUtil.MSE_OID_TAG,
                                                   Hex.hexify(psInfo.getProtocol().getValue()))
                             + (psInfo instanceof PSCInfo
                               ? EACServerUtil.makeTag(EACServerUtil.MSE_FILE_REFERENCE_TAG,
                                                       EACServerUtil.makeTag(EACServerUtil.DISCRETIONARY_DATA_TAG,
                                                                             createFileIdSeq(parameter)))
                               : "")
                             + EACServerUtil.makeTag(EACServerUtil.MSE_PRIVATE_KEY_REFERENCE_TAG,
                                                     Hex.hexify(psInfo.getKeyID()));
    CommandAPDU cmd = EACServerUtil.commandFromString(EACServerUtil.COMMAND_CHAINING_DISABLED
                                                        + EACServerUtil.MSE_INS
                                                        + (psInfo instanceof PSAInfo
                                                          ? EACServerUtil.MSE_SET_AT_PARAM_RI
                                                          : EACServerUtil.MSE_SET_DST_PARAM_COMP),
                                                      dataFieldString,
                                                      EACServerUtil.LENGTH_EXPECTED_NONE);
    InputAPDUInfoType tc = new InputAPDUInfoType();
    tc.setInputAPDU(cmd.getBytes());
    tcList.add(tc);

    if (psInfo instanceof PSAInfo)
    {
      dataFieldString = EACServerUtil.makeTag(EACServerUtil.GA_DATA_TAG,
                                              EACServerUtil.makeTag(SECTOR_PUBLIC_KEY_TAG,
                                                                    Hex.hexify(parameter.getPseudonymousSignatureKey())));
      cmd = EACServerUtil.commandFromString(EACServerUtil.COMMAND_CHAINING_DISABLED
                                              + EACServerUtil.GENERAL_AUTHENTICATE_HEADER,
                                            dataFieldString,
                                            EACServerUtil.LENGTH_EXPECTED_MAX_EXTENDED);
    }
    else
    {
      dataFieldString = EACServerUtil.makeTag(EACServerUtil.DISCRETIONARY_DATA_TAG,
                                              EACServerUtil.makeTag(SECTOR_PUBLIC_KEY_TAG,
                                                                    Hex.hexify(parameter.getPseudonymousSignatureKey()))
                                                + (psInfo instanceof PSCInfo
                                                  ? ""
                                                  : EACServerUtil.makeTag(INPUT_TAG,
                                                                          Hex.hexify(parameter.getSignatureInput()))));
      cmd = EACServerUtil.commandFromString(EACServerUtil.CLA_PROPRIETARY
                                              + EACServerUtil.PSO_COMPUTE_SIGNATURE_HEADER,
                                            dataFieldString,
                                            EACServerUtil.LENGTH_EXPECTED_MAX_EXTENDED);
    }
    tc = new InputAPDUInfoType();
    tc.setInputAPDU(cmd.getBytes());
    tcList.add(tc);

    return tcList;
  }

  @Override
  public Transmit parameterStep(PseudonymousSignatureParameter parameter, byte[] sh)
  {
    AssertUtil.notNull(parameter, "parameter");
    AssertUtil.notNull(sh, "slot handle");
    try
    {
      List<InputAPDUInfoType> listTransmitCommand = create(parameter, null);
      if (listTransmitCommand == null)
      {
        return null;
      }

      TransmitAPDUParameter tap = new TransmitAPDUParameter(listTransmitCommand);

      Transmit securedTransmitParameter = super.transmit.parameterStep(tap, sh);
      return securedTransmitParameter;
    }
    catch (IOException e)
    {
      throw new IllegalArgumentException("Internal error: " + e.getMessage(), e);
    }
  }

  @Override
  public PseudonymousSignatureResult resultStep(TransmitResponse result)
  {
    AssertUtil.notNull(result, "result");
    TransmitAPDUResult unsecuredResult = super.transmit.resultStep(result);
    return evaluate(unsecuredResult, unsecuredResult.getData().getOutputAPDU().size() == 2 ? new int[]{1}
      : null);
  }

  private static String createFileIdSeq(PseudonymousSignatureParameter parameter)
  {
    String frString = "";
    for ( byte[] fidBytes : parameter.getFidList() )
    {
      ASN1 fidASN1 = new ASN1(ASN1Constants.UNIVERSAL_TAG_OCTET_STRING, fidBytes);
      frString += Hex.hexify(fidASN1.getEncoded());
    }
    frString = EACServerUtil.makeTag("73", frString);
    if (parameter.isIncludeSpecificAttribute())
    {
      frString += EACServerUtil.makeTag("53", "00ff");
    }
    return frString;
  }

  public static boolean checkSignature(PseudonymousSignatureParameter parameter,
                                       PseudonymousSignatureResult result)
  {
    try
    {
      PSPublicKeyInfo psPublicKeyInfo = parameter.getPsPubKeyInfo();
      AlgorithmIdentifier outerAlgId = psPublicKeyInfo.getpSPublicKey().getAlgorithm();
      AlgorithmIdentifier innerAlgId = new AlgorithmIdentifier(outerAlgId.getParameters().getEncoded());
      ECParameterSpec params = ECUtil.parameterSpecFromAlgorithmIdentifier(innerAlgId);
      int fieldSizeBytes = params.getCurve().getField().getFieldSize() / 8;

      byte[] chipKeyBytes = ByteUtil.removeLeadingZero(psPublicKeyInfo.getpSPublicKey()
                                                                      .getSubjectPublicKey()
                                                                      .getValue());
      ECPoint pkICC = ECMath.pointFromBytes(chipKeyBytes, fieldSizeBytes);
      ECPoint pkM = ECMath.pointFromBytes(outerAlgId.getChildElementList().get(2).getValue(), fieldSizeBytes);
      ECPoint pkSector = ECMath.pointFromBytes(parameter.getPseudonymousSignatureKey(), fieldSizeBytes);
      OID protocolOID = parameter.getPsInfo().getProtocol();
      MessageDigest digest = DigestUtil.getDigestByOID(protocolOID);
      byte[] message = parameter.getSignatureInput();
      byte[] signature = result.getSignature();
      byte[] cBytes = ByteUtil.subbytes(signature, 0, digest.getDigestLength());
      BigInteger c = new BigInteger(1, cBytes);
      byte[] s1Bytes = ByteUtil.subbytes(signature, digest.getDigestLength(), digest.getDigestLength()
                                                                              + fieldSizeBytes);
      BigInteger s1 = new BigInteger(1, s1Bytes);
      BigInteger s2 = new BigInteger(1, ByteUtil.subbytes(signature, digest.getDigestLength()
                                                                     + s1Bytes.length));


      BigInteger a = params.getCurve().getA();
      BigInteger prime = ((ECFieldFp)params.getCurve().getField()).getP();

      ECPoint p1 = ECMath.multiplyECPoint(pkICC, c, a, prime);
      ECPoint p2 = ECMath.multiplyECPoint(params.getGenerator(), s1, a, prime);
      ECPoint p3 = ECMath.multiplyECPoint(pkM, s2, a, prime);
      ECPoint q1 = ECMath.addECPoints(ECMath.addECPoints(p1, p2, a, prime), p3, a, prime);

      byte[] toBeDigested = new byte[0];
      toBeDigested = ByteUtil.combine(toBeDigested,
                                      ByteUtil.trimByteArray(q1.getAffineX().toByteArray(), fieldSizeBytes));
      if (result.getFirstKey() != null)
      {
        ECPoint iSectorICC1 = ECMath.pointFromBytes(result.getFirstKey(), fieldSizeBytes);
        ECPoint p11 = ECMath.multiplyECPoint(iSectorICC1, c, a, prime);
        ECPoint p12 = ECMath.multiplyECPoint(pkSector, s1, a, prime);
        ECPoint a1 = ECMath.addECPoints(p11, p12, a, prime);
        toBeDigested = ByteUtil.combine(toBeDigested, ByteUtil.trimByteArray(iSectorICC1.getAffineX()
                                                                                        .toByteArray(),
                                                                             fieldSizeBytes));
        toBeDigested = ByteUtil.combine(toBeDigested,
                                        ByteUtil.trimByteArray(a1.getAffineX().toByteArray(), fieldSizeBytes));
      }
      if (result.getSecondKey() != null)
      {
        ECPoint iSectorICC2 = ECMath.pointFromBytes(result.getSecondKey(), fieldSizeBytes);
        ECPoint p21 = ECMath.multiplyECPoint(iSectorICC2, c, a, prime);
        ECPoint p22 = ECMath.multiplyECPoint(pkSector, s2, a, prime);
        ECPoint a2 = ECMath.addECPoints(p21, p22, a, prime);
        toBeDigested = ByteUtil.combine(toBeDigested, ByteUtil.trimByteArray(iSectorICC2.getAffineX()
                                                                                        .toByteArray(),
                                                                             fieldSizeBytes));
        toBeDigested = ByteUtil.combine(toBeDigested,
                                        ByteUtil.trimByteArray(a2.getAffineX().toByteArray(), fieldSizeBytes));
      }
      toBeDigested = ByteUtil.combine(toBeDigested, ByteUtil.trimByteArray(pkSector.getAffineX()
                                                                                   .toByteArray(),
                                                                           fieldSizeBytes));
      toBeDigested = ByteUtil.combine(toBeDigested, protocolOID.getEncoded());
      toBeDigested = ByteUtil.combine(toBeDigested, message);

      return ByteUtil.equals(cBytes, digest.digest(toBeDigested));
    }
    catch (IOException | NoSuchAlgorithmException e)
    {
      return false;
    }
  }
}

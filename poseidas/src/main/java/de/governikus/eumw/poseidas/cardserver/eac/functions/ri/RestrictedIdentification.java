/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardserver.eac.functions.ri;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import de.governikus.eumw.poseidas.cardbase.AssertUtil;
import de.governikus.eumw.poseidas.cardbase.Hex;
import de.governikus.eumw.poseidas.cardbase.asn1.ASN1;
import de.governikus.eumw.poseidas.cardbase.asn1.OID;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.si.RestrictedIdentificationInfo;
import de.governikus.eumw.poseidas.cardbase.constants.OIDConstants;
import de.governikus.eumw.poseidas.cardserver.EACServerUtil;
import de.governikus.eumw.poseidas.cardserver.eac.InputAPDUInfoTypeUtil;
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
import lombok.extern.slf4j.Slf4j;


/**
 * Implementation of RetrictedIdentification function.
 *
 * @see RetrictedIdentificationParameter
 * @see RetrictedIdentificationResult
 * @author Jens Wothe, jw@bos-bremen.de
 */
@Slf4j
public class RestrictedIdentification
  extends AbstractFunctionStep<RestrictedIdentificationParameter, RestrictedIdentificationResult>
  implements FunctionStep<RestrictedIdentificationParameter, RestrictedIdentificationResult>,
  TransmitCommandCreator<RestrictedIdentificationParameter>, TransmitResultEvaluator<RestrictedIdentificationResult>
{

  /**
   * Tag for sending first sector key to card.
   */
  private static final String FIRST_KEY_TAG = "A0";

  /**
   * Tag for sending second sector key to card.
   */
  private static final String SECOND_KEY_TAG = "A2";

  /**
   * Tag for first sector specific ID received from card.
   */
  private static final byte[] FIRST_ID_TAG = new byte[]{(byte)0x81};

  /**
   * Tag for second sector specific ID received from card.
   */
  private static final byte[] SECOND_ID_TAG = new byte[]{(byte)0x83};

  /**
   * Constructor with transmit.
   *
   * @param transmit transmit, <code>null</code> not permitted
   */
  public RestrictedIdentification(TransmitAPDU transmit)
  {
    super(transmit);
  }

  /** {@inheritDoc} */
  @Override
  public Transmit parameterStep(RestrictedIdentificationParameter parameter, byte[] sht)

  {
    AssertUtil.notNull(parameter, "parameter");
    AssertUtil.notNull(sht, "slot handle");
    try
    {
      List<InputAPDUInfoType> listTransmitCommand = create(parameter, null);
      if (listTransmitCommand == null)
      {
        return null;
      }

      TransmitAPDUParameter tap = new TransmitAPDUParameter(listTransmitCommand);

      return super.transmit.parameterStep(tap, sht);
    }
    catch (IOException e)
    {
      throw new IllegalArgumentException("Internal error: " + e.getMessage(), e);
    }
  }

  /** {@inheritDoc} */
  @Override
  public RestrictedIdentificationResult resultStep(TransmitResponse result)
  {
    AssertUtil.notNull(result, "result");
    TransmitAPDUResult unsecuredResult = super.transmit.resultStep(result);
    return evaluate(unsecuredResult,
                    unsecuredResult.getData().getOutputAPDU().size() == 2 ? DEFAULT_RESPONSE_INDICES_TO_EVALUATE_TWO_ID
                      : null);
  }

  // default indices (two ID)
  private static final int[] DEFAULT_RESPONSE_INDICES_TO_EVALUATE_TWO_ID = new int[]{0, 1};


  /** {@inheritDoc} */
  @Override
  public List<InputAPDUInfoType> create(RestrictedIdentificationParameter parameter) throws Exception
  {
    return create(parameter, null);
  }

  /** {@inheritDoc} */
  @Override
  public List<InputAPDUInfoType> create(RestrictedIdentificationParameter parameter,
                                        List<ResponseAPDU> acceptedResponseList)
    throws IOException
  {
    List<InputAPDUInfoType> tcList = new ArrayList<>();

    RestrictedIdentificationInfo riInfo = parameter.getRiInfo();
    String dataFieldString = EACServerUtil.makeTag(EACServerUtil.MSE_OID_TAG,
                                                   Hex.hexify(riInfo.getProtocol().getValue()))
                             + EACServerUtil.makeTag(EACServerUtil.MSE_PRIVATE_KEY_REFERENCE_TAG,
                                                     Hex.hexify(riInfo.getParams().getKeyID()));
    CommandAPDU cmd = EACServerUtil.commandFromString(EACServerUtil.COMMAND_CHAINING_DISABLED + EACServerUtil.MSE_INS
                                                      + EACServerUtil.MSE_SET_AT_PARAM_RI,
                                                      dataFieldString,
                                                      EACServerUtil.LENGTH_EXPECTED_NONE);
    InputAPDUInfoType tc = new InputAPDUInfoType();
    tc.setInputAPDU(cmd.getBytes());
    tc.getAcceptableStatusCode().addAll(InputAPDUInfoTypeUtil.RESPONSE_CODE_ACCEPT_OK_ONLY_BYTES_LIST);
    tcList.add(tc);

    // calculate expected length: length of ID plus 4 bytes for TLV structure
    OID oid = new OID(riInfo.getProtocol().getEncoded());
    String expectedIDLength = "";
    if (oid.equals(OIDConstants.OID_RI_DH_SHA_1) || oid.equals(OIDConstants.OID_RI_ECDH_SHA_1))
    {
      expectedIDLength = "18";
    }
    else if (oid.equals(OIDConstants.OID_RI_DH_SHA_224) || oid.equals(OIDConstants.OID_RI_ECDH_SHA_224))
    {
      expectedIDLength = "20";
    }
    else if (oid.equals(OIDConstants.OID_RI_DH_SHA_256) || oid.equals(OIDConstants.OID_RI_ECDH_SHA_256))
    {
      expectedIDLength = "24";
    }


    byte[] firstKey = parameter.getFirstKey();
    if (firstKey != null && firstKey.length > 0)
    {
      dataFieldString = EACServerUtil.makeTag(EACServerUtil.GA_DATA_TAG,
                                              EACServerUtil.makeTag(FIRST_KEY_TAG, Hex.hexify(firstKey)));
      cmd = EACServerUtil.commandFromString(EACServerUtil.COMMAND_CHAINING_DISABLED
                                            + EACServerUtil.GENERAL_AUTHENTICATE_HEADER,
                                            dataFieldString,
                                            expectedIDLength);
      tc = new InputAPDUInfoType();
      tc.setInputAPDU(cmd.getBytes());
      tc.getAcceptableStatusCode().addAll(InputAPDUInfoTypeUtil.RESPONSE_CODE_ACCEPT_OK_ONLY_BYTES_LIST);
      tcList.add(tc);
    }
    byte[] secondKey = parameter.getSecondKey();
    if (secondKey != null && secondKey.length > 0)
    {
      dataFieldString = EACServerUtil.makeTag(EACServerUtil.GA_DATA_TAG,
                                              EACServerUtil.makeTag(SECOND_KEY_TAG, Hex.hexify(secondKey)));
      cmd = EACServerUtil.commandFromString(EACServerUtil.COMMAND_CHAINING_DISABLED
                                            + EACServerUtil.GENERAL_AUTHENTICATE_HEADER,
                                            dataFieldString,
                                            expectedIDLength);
      tc = new InputAPDUInfoType();
      tc.setInputAPDU(cmd.getBytes());
      tc.getAcceptableStatusCode().addAll(InputAPDUInfoTypeUtil.RESPONSE_CODE_ACCEPT_OK_ONLY_BYTES_LIST);
      tcList.add(tc);
    }
    return tcList;
  }

  /** {@inheritDoc} */
  @Override
  public RestrictedIdentificationResult evaluate(TransmitAPDUResult transmitResult, int[] responseIndices)
  {
    if (transmitResult.getThrowable() != null)
    {
      return new RestrictedIdentificationResult(transmitResult.getThrowable());
    }
    responseIndices = TransmitResultEvaluator.Util.checkArguments(transmitResult, responseIndices);

    RestrictedIdentificationResult riResult = new RestrictedIdentificationResult();
    try
    {
      for ( int responseIndice : responseIndices )
      {
        ResponseAPDU r = new ResponseAPDU(transmitResult.getData().getOutputAPDU().get(responseIndice));
        byte[] data = r.getData();
        if (data == null)
        {
          continue;
        }
        ASN1 resASN1 = new ASN1(data);
        ASN1[] idData = resASN1.getChildElementsByDTagBytes(FIRST_ID_TAG);
        if (idData != null && idData.length == 1)
        {
          riResult.setFirstID(idData[0].getValue());
        }
        idData = resASN1.getChildElementsByDTagBytes(SECOND_ID_TAG);
        if (idData != null && idData.length == 1)
        {
          riResult.setSecondID(idData[0].getValue());
        }
      }
    }
    catch (Exception e)
    {
      if (log.isDebugEnabled())
      {
        log.debug("Error while evaluating transmit APDU", e);
      }
      riResult = new RestrictedIdentificationResult(e);
    }
    return riResult;
  }

  /** {@inheritDoc} */
  @Override
  public int getMinimumCount()
  {
    return 1;
  }

  /** {@inheritDoc} */
  @Override
  public int getMaximumCount()
  {
    return 2;
  }
}

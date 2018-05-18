/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardserver.eac.functions.readattr;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import de.governikus.eumw.poseidas.cardbase.AssertUtil;
import de.governikus.eumw.poseidas.cardbase.ByteUtil;
import de.governikus.eumw.poseidas.cardbase.Hex;
import de.governikus.eumw.poseidas.cardbase.asn1.ASN1;
import de.governikus.eumw.poseidas.cardbase.asn1.ASN1Constants;
import de.governikus.eumw.poseidas.cardbase.card.CoreCodeConstants;
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


public class ReadAttribute extends AbstractFunctionStep<ReadAttributeParameter, ReadAttributeResult>
  implements FunctionStep<ReadAttributeParameter, ReadAttributeResult>,
  TransmitCommandCreator<ReadAttributeParameter>, TransmitResultEvaluator<ReadAttributeResult>
{

  public ReadAttribute(TransmitAPDU transmit)
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
  public ReadAttributeResult evaluate(TransmitAPDUResult transmitResult, int[] responseIndices)
  {
    responseIndices = TransmitResultEvaluator.Util.checkArguments(transmitResult,
                                                                  responseIndices,
                                                                  getMinimumCount(),
                                                                  getMaximumCount());
    if (transmitResult.getThrowable() != null)
    {
      return new ReadAttributeResult(transmitResult.getThrowable());
    }

    try
    {
      for ( int i : responseIndices )
      {
        ResponseAPDU r = new ResponseAPDU(transmitResult.getData().getOutputAPDU().get(i));
        if (r.getSW() != CoreCodeConstants.SUCCESSFULLY_PROCESSED
            && ((i == responseIndices[0] && r.getSW1() != 0x62) || i != responseIndices[0]))
        {
          return new ReadAttributeResult(new IllegalStateException("read specific attribute not performed"));
        }
      }
    }
    catch (Exception e)
    {
      return new ReadAttributeResult(e);
    }


    final byte[] ddtTag = Hex.parse(EACServerUtil.DISCRETIONARY_DATA_TAG);
    final byte[] attributeTag = Hex.parse(EACServerUtil.GET_DATA_ATTRIBUTE_TAG);

    List<byte[]> resultList = new ArrayList<>();
    ResponseAPDU r = new ResponseAPDU(transmitResult.getData().getOutputAPDU().get(responseIndices[1]));
    ASN1 sequence = new ASN1(ASN1Constants.UNIVERSAL_TAG_SEQUENCE_CONSTRUCTED, r.getData());

    try
    {
      for ( ASN1 ddt : sequence.getChildElements() )
      {
        if (!ByteUtil.equals(ddt.getDTagBytes(), ddtTag))
        {
          continue;
        }
        for ( ASN1 child : ddt.getChildElements() )
        {
          if (!ByteUtil.equals(child.getDTagBytes(), attributeTag))
          {
            continue;
          }
          resultList.add(child.getValue());
        }
      }
    }
    catch (IOException e)
    {
      return new ReadAttributeResult(e);
    }

    return new ReadAttributeResult(resultList);
  }

  @Override
  public List<InputAPDUInfoType> create(ReadAttributeParameter parameter)
  {
    return this.create(parameter, null);
  }

  @Override
  public List<InputAPDUInfoType> create(ReadAttributeParameter parameter,
                                        List<ResponseAPDU> acceptedResponseList)
  {
    List<InputAPDUInfoType> tcList = new ArrayList<>();

    String dataFieldString = EACServerUtil.makeTag(EACServerUtil.PRESENT_USER_DATA_TAG,
                                                   EACServerUtil.makeTag(EACServerUtil.DISCRETIONARY_DATA_TAG,
                                                                         EACServerUtil.makeTag(EACServerUtil.PRESENT_USER_SECTOR_PUBLIC_KEY_HASH_TAG,
                                                                                               Hex.hexify(parameter.getSectorPublicKeyHash()))));
    CommandAPDU cmd = EACServerUtil.commandFromString(EACServerUtil.COMMAND_CHAINING_DISABLED
                                                        + EACServerUtil.PRESENT_USER_HEADER,
                                                      dataFieldString,
                                                      EACServerUtil.LENGTH_EXPECTED_NONE);
    InputAPDUInfoType tc = new InputAPDUInfoType();
    tc.setInputAPDU(cmd.getBytes());
    tcList.add(tc);

    cmd = EACServerUtil.commandFromString(EACServerUtil.COMMAND_CHAINING_DISABLED
                                            + EACServerUtil.GET_DATA_INS + EACServerUtil.GET_DATA_SPEC_ATTR,
                                          null,
                                          EACServerUtil.LENGTH_EXPECTED_MAX);

    tc = new InputAPDUInfoType();
    tc.setInputAPDU(cmd.getBytes());
    tcList.add(tc);

    return tcList;
  }

  @Override
  public Transmit parameterStep(ReadAttributeParameter parameter, byte[] sh)
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
    catch (Exception e)
    {
      throw new IllegalArgumentException("Internal error: " + e.getMessage(), e);
    }
  }

  @Override
  public ReadAttributeResult resultStep(TransmitResponse result)
  {
    AssertUtil.notNull(result, "result");
    TransmitAPDUResult unsecuredResult = super.transmit.resultStep(result);
    return evaluate(unsecuredResult, unsecuredResult.getData().getOutputAPDU().size() == 2 ? new int[]{0, 1}
      : null);
  }
}

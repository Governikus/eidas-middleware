/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardserver.eac.functions.writeattrreq;

import java.util.ArrayList;
import java.util.List;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import de.governikus.eumw.poseidas.cardbase.AssertUtil;
import de.governikus.eumw.poseidas.cardbase.Hex;
import de.governikus.eumw.poseidas.cardbase.card.SmartCardCodeConstants;
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


public class WriteAttributeRequest extends
  AbstractFunctionStep<WriteAttributeRequestParameter, WriteAttributeRequestResult> implements
  FunctionStep<WriteAttributeRequestParameter, WriteAttributeRequestResult>,
  TransmitCommandCreator<WriteAttributeRequestParameter>,
  TransmitResultEvaluator<WriteAttributeRequestResult>
{

  public WriteAttributeRequest(TransmitAPDU transmit)
  {
    super(transmit);
  }

  @Override
  public int getMinimumCount()
  {
    return 3;
  }

  @Override
  public int getMaximumCount()
  {
    return 3;
  }

  @Override
  public WriteAttributeRequestResult evaluate(TransmitAPDUResult transmitResult, int[] responseIndices)
  {
    responseIndices = TransmitResultEvaluator.Util.checkArguments(transmitResult,
                                                                  responseIndices,
                                                                  getMinimumCount(),
                                                                  getMaximumCount());
    if (transmitResult.getThrowable() != null)
    {
      return new WriteAttributeRequestResult(transmitResult.getThrowable());
    }

    for ( int i : responseIndices )
    {
      ResponseAPDU r = new ResponseAPDU(transmitResult.getData().getOutputAPDU().get(i));
      if (r.getSW() != SmartCardCodeConstants.SUCCESSFULLY_PROCESSED
          && ((i == responseIndices[0] && r.getSW1() != 0x62) || i != responseIndices[0]))
      {
        return new WriteAttributeRequestResult(
                                               new IllegalStateException(
                                                                         "write attribute request not performed"));
      }
    }
    return new WriteAttributeRequestResult(true);
  }

  @Override
  public List<InputAPDUInfoType> create(WriteAttributeRequestParameter parameter)
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

    dataFieldString = EACServerUtil.makeTag(EACServerUtil.PUT_DATA_DATA_TAG,
                                            Hex.hexify(parameter.getAttributeRequests()));
    cmd = EACServerUtil.commandFromString(EACServerUtil.COMMAND_CHAINING_DISABLED
                                            + EACServerUtil.PUT_DATA_INS + EACServerUtil.PUT_DATA_ATTR_REQ,
                                          dataFieldString,
                                          EACServerUtil.LENGTH_EXPECTED_NONE);

    tc = new InputAPDUInfoType();
    tc.setInputAPDU(cmd.getBytes());
    tcList.add(tc);

    dataFieldString = EACServerUtil.makeTag(EACServerUtil.MSE_SET_AT_RESTORE_SESSION_TAG,
                                            EACServerUtil.makeTag("81", "00"));
    cmd = EACServerUtil.commandFromString(EACServerUtil.COMMAND_CHAINING_DISABLED + EACServerUtil.MSE_INS
                                            + EACServerUtil.MSE_SET_AT_RESTORE_SESSION,
                                          dataFieldString,
                                          EACServerUtil.LENGTH_EXPECTED_NONE);

    tc = new InputAPDUInfoType();
    tc.setInputAPDU(cmd.getBytes());
    tcList.add(tc);

    return tcList;
  }

  @Override
  public List<InputAPDUInfoType> create(WriteAttributeRequestParameter parameter,
                                        List<ResponseAPDU> acceptedResponseList)
  {
    return this.create(parameter, null);
  }

  @Override
  public Transmit parameterStep(WriteAttributeRequestParameter parameter, byte[] sh)
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
  public WriteAttributeRequestResult resultStep(TransmitResponse result)
  {
    AssertUtil.notNull(result, "result");
    TransmitAPDUResult unsecuredResult = super.transmit.resultStep(result);
    return evaluate(unsecuredResult, unsecuredResult.getData().getOutputAPDU().size() == 3 ? new int[]{0, 1,
                                                                                                       2}
      : null);
  }
}

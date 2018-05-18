/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardserver.eac.functions.update;

import java.util.List;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import de.governikus.eumw.poseidas.cardbase.AssertUtil;
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


/**
 * Function for updating files on card.
 * 
 * @author Arne Stahlbock, arne.stahlbock@governikus.com
 */
public class Update extends AbstractFunctionStep<UpdateParameter, UpdateResult> implements
  FunctionStep<UpdateParameter, UpdateResult>, TransmitCommandCreator<UpdateParameter>,
  TransmitResultEvaluator<UpdateResult>
{

  /**
   * Constructor with transmit.
   * 
   * @param transmit transmit, <code>null</code> not permitted
   */
  public Update(TransmitAPDU transmit)
  {
    super(transmit);
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
    return 1;
  }

  /** {@inheritDoc} */
  @Override
  public List<InputAPDUInfoType> create(UpdateParameter parameter)
  {
    return this.create(parameter, null);
  }

  /** {@inheritDoc} */
  @Override
  public List<InputAPDUInfoType> create(UpdateParameter parameter, List<ResponseAPDU> acceptedResponseList)
  {
    CommandAPDU command = new CommandAPDU(0x00, 0xd6, parameter.getSfi() == null
      ? parameter.getOffset() / 256 : parameter.getSfi() | 0x80, parameter.getOffset() % 256,
                                          parameter.getData());
    return InputAPDUInfoTypeUtil.create(command, acceptedResponseList);
  }

  /** {@inheritDoc} */
  @Override
  public Transmit parameterStep(UpdateParameter parameter, byte[] sht)
  {
    AssertUtil.notNull(sht, "slot handle");
    List<InputAPDUInfoType> listTransmitCommand = create(parameter, null);
    if (listTransmitCommand == null)
    {
      return null;
    }
    TransmitAPDUParameter tap = new TransmitAPDUParameter(listTransmitCommand);

    Transmit securedTransmitParameter = super.transmit.parameterStep(tap, sht);
    return securedTransmitParameter;
  }

  /** {@inheritDoc} */
  @Override
  public UpdateResult resultStep(TransmitResponse result)
  {
    AssertUtil.notNull(result, "result");
    TransmitAPDUResult unsecuredResult = super.transmit.resultStep(result);
    return evaluate(unsecuredResult, null);
  }

  /** {@inheritDoc} */
  @Override
  public UpdateResult evaluate(TransmitAPDUResult transmitResult, int[] responseIndices)
  {
    responseIndices = TransmitResultEvaluator.Util.checkArguments(transmitResult,
                                                                  responseIndices,
                                                                  getMinimumCount(),
                                                                  getMaximumCount());
    if (transmitResult.getThrowable() != null)
    {
      return new UpdateResult(transmitResult.getThrowable());
    }
    byte[] resp = transmitResult.getData().getOutputAPDU().get(responseIndices[0]);
    UpdateResult result = new UpdateResult(resp[0] == (byte)0x90 && resp[1] == 0x00 ? Boolean.TRUE
      : Boolean.FALSE);
    return result;
  }
}

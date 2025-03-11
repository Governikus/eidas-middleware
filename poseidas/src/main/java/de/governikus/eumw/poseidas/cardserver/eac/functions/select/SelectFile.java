/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardserver.eac.functions.select;

import java.util.List;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import de.governikus.eumw.poseidas.cardbase.AssertUtil;
import de.governikus.eumw.poseidas.cardbase.ByteUtil;
import de.governikus.eumw.poseidas.cardbase.Hex;
import de.governikus.eumw.poseidas.cardbase.card.SmartCardCodeConstants;
import de.governikus.eumw.poseidas.cardserver.eac.InputAPDUInfoTypeUtil;
import de.governikus.eumw.poseidas.cardserver.eac.functions.FunctionStep;
import de.governikus.eumw.poseidas.cardserver.eac.functions.TransmitCommandCreator;
import de.governikus.eumw.poseidas.cardserver.eac.functions.TransmitResultEvaluator;
import de.governikus.eumw.poseidas.cardserver.eac.functions.impl.AbstractFunctionStep;
import de.governikus.eumw.poseidas.cardserver.eac.functions.impl.FileParameter;
import de.governikus.eumw.poseidas.cardserver.eac.functions.transmitAPDU.TransmitAPDU;
import de.governikus.eumw.poseidas.cardserver.eac.functions.transmitAPDU.TransmitAPDUParameter;
import de.governikus.eumw.poseidas.cardserver.eac.functions.transmitAPDU.TransmitAPDUResult;
import iso.std.iso_iec._24727.tech.schema.InputAPDUInfoType;
import iso.std.iso_iec._24727.tech.schema.Transmit;
import iso.std.iso_iec._24727.tech.schema.TransmitResponse;


/**
 * Implementation of select file function.
 *
 * @see FileParameter
 * @see SelectResult
 * @author Jens Wothe, jw@bos-bremen.de
 */
public class SelectFile extends AbstractFunctionStep<FileParameter, SelectResult>
  implements FunctionStep<FileParameter, SelectResult>, TransmitCommandCreator<FileParameter>,
  TransmitResultEvaluator<SelectResult>
{

  /**
   * Constructor with transmit.
   *
   * @param transmit transmit, <code>null</code> not permitted
   */
  public SelectFile(TransmitAPDU transmit)
  {
    super(transmit);
  }

  /** {@inheritDoc} */
  @Override
  public Transmit parameterStep(FileParameter parameter, byte[] sht)
  {
    AssertUtil.notNull(parameter, "parameter");
    AssertUtil.notNull(sht, "slot handle");
    List<InputAPDUInfoType> listTransmitCommand = create(parameter, null);
    if (listTransmitCommand == null)
    {
      return null;
    }
    TransmitAPDUParameter tap = new TransmitAPDUParameter(listTransmitCommand);

    return super.transmit.parameterStep(tap, sht);
  }

  /** {@inheritDoc} */
  @Override
  public SelectResult resultStep(TransmitResponse result)
  {
    AssertUtil.notNull(result, "result");
    TransmitAPDUResult unsecuredResult = super.transmit.resultStep(result);
    return evaluate(unsecuredResult, null);
  }

  /** {@inheritDoc} */
  @Override
  public List<InputAPDUInfoType> create(FileParameter parameter)
  {
    return this.create(parameter, null);
  }

  /** {@inheritDoc} */
  @Override
  public List<InputAPDUInfoType> create(FileParameter parameter, List<ResponseAPDU> acceptedResponseList)
  {
    CommandAPDU command;
    if (parameter.useFCP())
    {
      command = new CommandAPDU(ByteUtil.combine(ByteUtil.combine(Hex.parse("00a4020402"), parameter.getEFID()),
                                                 new byte[]{0x00}));
    }
    else
    {
      command = new CommandAPDU(ByteUtil.combine(Hex.parse("00a4020c02"), parameter.getEFID()));
    }
    return InputAPDUInfoTypeUtil.create(command, acceptedResponseList);
  }

  @Override
  public SelectResult evaluate(TransmitAPDUResult transmitResult, int[] responseIndices)
  {
    if (transmitResult.getThrowable() != null)
    {
      return new SelectResult(transmitResult.getThrowable());
    }
    responseIndices = TransmitResultEvaluator.Util.checkArguments(transmitResult, responseIndices);
    ResponseAPDU resp = new ResponseAPDU(transmitResult.getData().getOutputAPDU().get(responseIndices[0]));
    return new SelectResult(resp.getSW() == SmartCardCodeConstants.SUCCESSFULLY_PROCESSED ? Boolean.TRUE
      : Boolean.FALSE, resp.getData());
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
}

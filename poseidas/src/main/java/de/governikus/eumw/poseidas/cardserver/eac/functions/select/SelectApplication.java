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
import de.governikus.eumw.poseidas.cardbase.Hex;
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
 * Implementation of select application function.
 *
 * @see FileParameter
 * @see SelectResult
 * @author Jens Wothe, jw@bos-bremen.de
 */
public class SelectApplication extends AbstractFunctionStep<FileParameter, SelectResult>
  implements FunctionStep<FileParameter, SelectResult>, TransmitCommandCreator<FileParameter>,
  TransmitResultEvaluator<SelectResult>
{

  /**
   * Constructor with transmit.
   *
   * @param transmit transmit, <code>null</code> not permitted
   */
  public SelectApplication(TransmitAPDU transmit)
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
    CommandAPDU command = null;
    if (parameter.getDFID() != null)
    {
      command = new CommandAPDU(Hex.parse("00a4040c" + Hex.hexify(parameter.getDFID().length)
                                          + Hex.hexify(parameter.getDFID())));
    }
    else if (parameter.getAID() != null)
    {
      command = new CommandAPDU(Hex.parse("00a4040c" + Hex.hexify(parameter.getAID().length)
                                          + Hex.hexify(parameter.getAID())));
    }
    else
    {
      return null;
    }
    return InputAPDUInfoTypeUtil.create(command, acceptedResponseList);
  }

  /** {@inheritDoc} */
  @Override
  public SelectResult evaluate(TransmitAPDUResult transmitResult, int[] responseIndices)
  {
    if (transmitResult.getThrowable() != null)
    {
      return new SelectResult(transmitResult.getThrowable());
    }
    responseIndices = TransmitResultEvaluator.Util.checkArguments(transmitResult, responseIndices);
    byte[] resp = transmitResult.getData().getOutputAPDU().get(responseIndices[0]);
    return new SelectResult(resp[0] == (byte)0x90 && resp[1] == 0x00 ? Boolean.TRUE : Boolean.FALSE);
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

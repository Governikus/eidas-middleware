/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardserver.eac.functions.read;

import java.io.FileNotFoundException;
import java.util.List;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import de.governikus.eumw.poseidas.cardbase.AssertUtil;
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
 * Implementation of Read function.
 *
 * @see FileParameter
 * @see ReadResult
 * @author Jens Wothe, jw@bos-bremen.de
 */
public class Read extends AbstractFunctionStep<ReadParameter, ReadResult> implements
  FunctionStep<ReadParameter, ReadResult>, TransmitCommandCreator<ReadParameter>, TransmitResultEvaluator<ReadResult>
{

  /**
   * Constructor with transmit.
   *
   * @param transmit transmit, <code>null</code> not permitted
   */
  public Read(TransmitAPDU transmit)
  {
    super(transmit);
  }

  /** {@inheritDoc} */
  @Override
  public Transmit parameterStep(ReadParameter parameter, byte[] sht)
  {
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
  public ReadResult resultStep(TransmitResponse result)
  {
    AssertUtil.notNull(result, "result");
    TransmitAPDUResult unsecuredResult = super.transmit.resultStep(result);
    return evaluate(unsecuredResult, null);
  }

  /** {@inheritDoc} */
  @Override
  public List<InputAPDUInfoType> create(ReadParameter parameter)
  {
    return this.create(parameter, null);
  }

  /** {@inheritDoc} */
  @Override
  public List<InputAPDUInfoType> create(ReadParameter parameter, List<ResponseAPDU> acceptedResponseList)
  {
    CommandAPDU command = null;
    if (parameter == null)
    {
      command = new CommandAPDU(Hex.parse("00b00000000000"));
    }
    else
    {
      command = new CommandAPDU((byte)0x00, (byte)0xb0,
                                parameter.getSfi() == null ? (byte)(parameter.getOffset() / 256)
                                  : parameter.getSfi() | 0x80,
                                (byte)(parameter.getOffset() % 256), null, parameter.getLength());
    }
    return InputAPDUInfoTypeUtil.create(command, acceptedResponseList);
  }

  /** {@inheritDoc} */
  @Override
  public ReadResult evaluate(TransmitAPDUResult transmitResult, int[] responseIndices)
  {
    if (transmitResult.getThrowable() != null)
    {
      return new ReadResult(transmitResult.getThrowable());
    }
    responseIndices = TransmitResultEvaluator.Util.checkArguments(transmitResult, responseIndices);
    ResponseAPDU resp = new ResponseAPDU(transmitResult.getData().getOutputAPDU().get(responseIndices[0]));
    if (resp.getSW() == SmartCardCodeConstants.SUCCESSFULLY_PROCESSED
        || resp.getSW() == SmartCardCodeConstants.EOF_READ)
    {
      return new ReadResult(resp.getData());
    }
    if (resp.getSW() == SmartCardCodeConstants.FILE_NOT_FOUND
        || resp.getSW() == SmartCardCodeConstants.COMMAND_NOT_ALLOWED)
    {
      return new ReadResult(new FileNotFoundException("file not found on card"));
    }
    return new ReadResult(new RuntimeException("error reading file, error code: " + resp.getSW()));
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

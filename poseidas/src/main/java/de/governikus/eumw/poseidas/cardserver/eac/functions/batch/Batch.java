/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardserver.eac.functions.batch;

import java.util.List;

import de.governikus.eumw.poseidas.cardbase.AssertUtil;
import de.governikus.eumw.poseidas.cardserver.eac.functions.FunctionStep;
import de.governikus.eumw.poseidas.cardserver.eac.functions.impl.AbstractFunctionStep;
import de.governikus.eumw.poseidas.cardserver.eac.functions.transmitAPDU.TransmitAPDU;
import de.governikus.eumw.poseidas.cardserver.eac.functions.transmitAPDU.TransmitAPDUParameter;
import de.governikus.eumw.poseidas.cardserver.eac.functions.transmitAPDU.TransmitAPDUResult;
import iso.std.iso_iec._24727.tech.schema.InputAPDUInfoType;
import iso.std.iso_iec._24727.tech.schema.Transmit;
import iso.std.iso_iec._24727.tech.schema.TransmitResponse;


/**
 * Implementation of batch function (multiple commands).
 *
 * @see BatchParameter
 * @author Jens Wothe, jw@bos-bremen.de
 */
public class Batch extends AbstractFunctionStep<BatchParameter, TransmitAPDUResult>
  implements FunctionStep<BatchParameter, TransmitAPDUResult>
{

  /**
   * Constructor with transmit.
   *
   * @param transmit transmit, <code>null</code> not permitted
   */
  public Batch(TransmitAPDU transmit)
  {
    super(transmit);
  }

  /** {@inheritDoc} */
  @Override
  public Transmit parameterStep(BatchParameter parameter, byte[] sht)
  {
    AssertUtil.notNull(parameter, "parameter");
    AssertUtil.notNull(sht, "slot handle");

    List<InputAPDUInfoType> listTransmitCommand = parameter.getTransmitCommandList();
    TransmitAPDUParameter tap = new TransmitAPDUParameter(listTransmitCommand);
    return super.transmit.parameterStep(tap, sht);
  }

  /** {@inheritDoc} */
  @Override
  public TransmitAPDUResult resultStep(TransmitResponse result)
  {
    AssertUtil.notNull(result, "result");
    return super.transmit.resultStep(result);
  }
}

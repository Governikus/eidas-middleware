/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardserver.eac.functions.transmitAPDU;

import de.governikus.eumw.poseidas.cardserver.eac.TransmitResult;
import de.governikus.eumw.poseidas.cardserver.eac.functions.FunctionResult;
import iso.std.iso_iec._24727.tech.schema.TransmitResponse;


/**
 * Implementation of TransmitAPDU output parameter.
 *
 * @see TransmitAPDU
 * @see TransmitAPDUParameter
 * @author Jens Wothe, jw@bos-bremen.de
 */
public class TransmitAPDUResult extends TransmitResult implements FunctionResult<TransmitResponse>
{

  /**
   * Constructor.
   */
  public TransmitAPDUResult()
  {
    super();
  }

  /**
   * Constructor with list of responses.
   *
   * @param responseList list of responses
   */
  public TransmitAPDUResult(TransmitResponse responseList)
  {
    super(responseList);
  }

  /**
   * Constructor with list of responses.
   *
   * @param responseList list of responses
   * @param throwable throwable
   */
  TransmitAPDUResult(TransmitResponse responseList, Throwable throwable)
  {
    super(responseList, throwable);
  }
}

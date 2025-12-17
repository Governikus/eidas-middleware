/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardserver.eac;

import de.governikus.eumw.poseidas.cardserver.eac.functions.transmitAPDU.TransmitAPDU;
import iso.std.iso_iec._24727.tech.schema.TransmitResponse;


/**
 * Implementation of transmit result.
 *
 * @see TransmitAPDU
 * @author Jens Wothe, jw@bos-bremen.de
 */
public class TransmitResult extends AbstractResult<TransmitResponse> implements Result<TransmitResponse>
{

  /**
   * Gets index of throwable to indicate on which command error occured.
   *
   * @return the indexOfThrowable
   */
  public final int getIndexOfThrowable()
  {
    return super.getThrowable() == null ? -1 : super.getData().getOutputAPDU().size() - 1;
  }

  /**
   * Constructor.
   */
  public TransmitResult()
  {
    super();
  }

  /**
   * Constructor.
   *
   * @param data data
   * @param throwable throwable
   */
  public TransmitResult(TransmitResponse data, Throwable throwable)
  {
    super(data, throwable);
  }

  /**
   * Constructor.
   *
   * @param data data
   */
  public TransmitResult(TransmitResponse data)
  {
    this(data, null);
  }

}

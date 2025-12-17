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
import de.governikus.eumw.poseidas.cardserver.eac.functions.FunctionParameter;
import de.governikus.eumw.poseidas.cardserver.eac.functions.read.Read;
import de.governikus.eumw.poseidas.cardserver.eac.functions.read.ReadResult;
import iso.std.iso_iec._24727.tech.schema.InputAPDUInfoType;


/**
 * Implementation of file parameter for application selection, file selection and reading.
 *
 * @see Read
 * @see FileSelect
 * @see ApplicationSelect
 * @see ReadResult
 * @author Jens Wothe, jw@bos-bremen.de
 */
public class BatchParameter implements FunctionParameter
{

  private List<InputAPDUInfoType> transmitCommandList = null;

  /**
   * Constructor.
   *
   * @param file_id if of file (EF)
   * @param dfid id of DF or <code>null</code>
   * @param aid id of application or <code>null</code>
   * @throws IllegalArgumentException arguments invalid
   */
  public BatchParameter(List<InputAPDUInfoType> transmitCommandList)
  {
    super();
    AssertUtil.notNullOrEmpty(transmitCommandList, "transmit command list");
    this.transmitCommandList = transmitCommandList;
  }

  /**
   * @return the transmitCommandList
   */
  public final List<InputAPDUInfoType> getTransmitCommandList()
  {
    return transmitCommandList;
  }
}

/*
 * Copyright (c) 2019 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardserver.eac.functions.transmitAPDU;

import java.util.List;

import de.governikus.eumw.poseidas.cardserver.eac.TransmitParameter;
import de.governikus.eumw.poseidas.cardserver.eac.functions.FunctionParameter;
import iso.std.iso_iec._24727.tech.schema.InputAPDUInfoType;


/**
 * Implementation of TransmitAPDU input parameter.
 *
 * @see TransmitAPDU
 * @see TransmitAPDUResult
 * @author Jens Wothe, jw@bos-bremen.de
 */
public class TransmitAPDUParameter extends TransmitParameter implements FunctionParameter
{

  /**
   * Constructor with list of commands.
   *
   * @param commandList list of commands
   */
  public TransmitAPDUParameter(List<InputAPDUInfoType> commandList)
  {
    super(commandList);
  }
}

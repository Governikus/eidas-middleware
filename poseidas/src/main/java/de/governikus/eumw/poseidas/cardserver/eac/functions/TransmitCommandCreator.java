/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardserver.eac.functions;

import java.util.List;

import javax.smartcardio.ResponseAPDU;

import iso.std.iso_iec._24727.tech.schema.InputAPDUInfoType;



/**
 * Interface for creator of a transmit command.
 *
 * @author Jens Wothe, jw@bos-bremen.de
 */
public interface TransmitCommandCreator<S extends FunctionParameter> extends APDUCountRestricted
{

  /**
   * Creates list of transmit commands for parameter (one or more plain commands, accepting all response
   * codes).
   *
   * @param parameter parameter
   * @return transmit commands
   * @throws Exception when creating fails, exception according internal creation steps
   */
  public List<InputAPDUInfoType> create(S parameter) throws Exception;

  /**
   * Creates list of transmit commands for parameter (one or more plain commands).
   *
   * @param parameter parameter
   * @param acceptedResponseList optional list of only acceptable responses, batch execution is to be stopped
   *          on first not acceptable response code
   * @return transmit commands
   * @throws Exception when creating fails, exception according internal creation steps
   */
  public List<InputAPDUInfoType> create(S parameter, List<ResponseAPDU> acceptedResponseList)
    throws Exception;

}

/*
 * Copyright (c) 2019 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardserver.eac;

import java.util.List;

import de.governikus.eumw.poseidas.cardserver.eac.functions.transmitAPDU.TransmitAPDU;
import iso.std.iso_iec._24727.tech.schema.InputAPDUInfoType;


/**
 * Implementation of transmit parameter.
 *
 * @see TransmitAPDU
 * @author Jens Wothe, jw@bos-bremen.de
 */
public class TransmitParameter implements Parameter
{

  private boolean beginTransaction = false;

  private boolean endTransaction = false;

  private List<InputAPDUInfoType> commandList = null;

  /**
   * Constructor.
   */
  public TransmitParameter()
  {
    super();
  }

  /**
   * Constructor.
   *
   * @param data data
   */
  public TransmitParameter(List<InputAPDUInfoType> commandList)
  {
    super();
    this.commandList = commandList;
  }

  /**
   * Gets list of commands (normally secured by external instance as a server).
   *
   * @return list of commands (normally secured using Secure Messaging)
   */
  public final List<InputAPDUInfoType> getCommandList()
  {
    return commandList;
  }

  /**
   * Checks transaction is to begin before communication with card (blocking terminal).
   *
   * @return <code>true</code> when beginning transaction with block
   */
  public boolean isBeginTransaction()
  {
    return beginTransaction;
  }

  /**
   * Sets flag to begin transaction before communication with card (block terminal).
   *
   * @param beginTransaction <code>true</code> to begin transaction with block, otherwise <code>false</code>
   */
  public void setBeginTransaction(boolean beginTransaction)
  {
    this.beginTransaction = beginTransaction;
  }


  /**
   * Checks transaction is to end after communication with card (release terminal).
   *
   * @return <code>true</code> when ending transaction with block
   */
  public boolean isEndTransaction()
  {
    return endTransaction;
  }


  /**
   * Sets flag to end transaction after communication with card (releasing terminal).
   *
   * @param endTransaction <code>true</code> to end transaction with block, otherwise <code>false</code>
   */
  public void setEndTransaction(boolean endTransaction)
  {
    this.endTransaction = endTransaction;
  }
}

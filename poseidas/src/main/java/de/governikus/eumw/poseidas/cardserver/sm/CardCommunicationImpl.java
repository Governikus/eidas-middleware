/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardserver.sm;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import de.governikus.eumw.poseidas.cardbase.card.CommandAPDUConstants;
import lombok.Getter;
import lombok.Setter;


/**
 * Implementation of card communication information.
 *
 * @author Jens Wothe, jw@bos-bremen.de
 */
public class CardCommunicationImpl implements CardCommunication
{

  // plaintext commands
  @Getter
  private CommandAPDU[] plaintextCommands;

  // encrypted commands
  @Getter
  private CommandAPDU[] encryptedCommands;

  // plaintext responses
  @Getter
  private ResponseAPDU[] plaintextResponses;

  // encrypted responses
  @Getter
  private ResponseAPDU[] encryptedResponses;

  // throwable/exception
  @Getter
  @Setter
  private Throwable throwable = null;

  /**
   * Constructor with plaintext commands.
   * 
   * @param commands plaintext commands, <code>null</code> or empty array not permitted, <code>null</code> or too short
   *          array elements (at least 4 bytes) not permitted
   */
  public CardCommunicationImpl(CommandAPDU[] plaintextCommands)
  {
    super();
    this.setPlaintextCommands(plaintextCommands);
  }

  private void setPlaintextCommands(CommandAPDU... commands)
  {
    if (commands == null)
    {
      throw new IllegalArgumentException("command array not permitted as null");
    }
    if (commands.length < 1)
    {
      throw new IllegalArgumentException("empty command-array not permitted");
    }
    for ( CommandAPDU c : commands )
    {
      if (c == null || c.getBytes() == null)
      {
        throw new IllegalArgumentException("command of array not permitted as null");
      }
      if (c.getBytes().length < CommandAPDUConstants.COUNT_HEADER)
      {
        throw new IllegalArgumentException("command of array not permitted as incomplete command, at least 4 bytes required");
      }
    }
    this.plaintextCommands = commands;
  }

  /** {@inheritDoc} */
  @Override
  public void setEncryptedCommands(CommandAPDU... commands)
  {
    if (commands == null)
    {
      throw new IllegalArgumentException("command array not permitted as null");
    }
    if (commands.length < 1)
    {
      throw new IllegalArgumentException("empty command-array not permitted");
    }
    for ( CommandAPDU command : commands )
    {
      if (command == null || command.getBytes() == null)
      {
        throw new IllegalArgumentException("command of array not permitted as null");
      }
      if (command.getBytes().length < CommandAPDUConstants.COUNT_HEADER)
      {
        throw new IllegalArgumentException("command of array not permitted as incomplete command, at least 4 bytes required");
      }
    }
    this.encryptedCommands = commands;
  }

  /** {@inheritDoc} */
  @Override
  public void setPlaintextResponses(ResponseAPDU... responses)
  {
    if (responses != null)
    {
      for ( ResponseAPDU r : responses )
      {
        if (r == null || r.getBytes() == null)
        {
          throw new IllegalArgumentException("response not permitted as null");
        }
        if (r.getBytes().length < 2)
        {
          throw new IllegalArgumentException("illegal response, response expected to possess at least 2 bytes");
        }
      }
    }
    this.plaintextResponses = responses;
  }

  /** {@inheritDoc} */
  @Override
  public void setEncryptedResponses(ResponseAPDU... responses)
  {
    if (responses != null)
    {
      for ( ResponseAPDU r : responses )
      {
        if (r == null || r.getBytes() == null)
        {
          throw new IllegalArgumentException("response not permitted as null");
        }
        if (r.getBytes().length < 2)
        {
          throw new IllegalArgumentException("illegal response, response expected to possess at least 2 bytes");
        }
      }
    }
    this.encryptedResponses = responses;
  }
}

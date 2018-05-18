/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardserver.sm;

import java.util.Arrays;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import de.governikus.eumw.poseidas.cardbase.card.CommandAPDUConstants;


/**
 * Implementation of card communication information.
 * 
 * @author Jens Wothe, jw@bos-bremen.de
 */
public class CardCommunicationImpl implements CardCommunication
{

  // commands
  private CommandAPDU[] commands = null;

  // flag to indicate finished communication phase
  private boolean finished = false;

  // phase
  private int phase = PHASE_PREPARE;

  // responses
  private ResponseAPDU[] responses = null;

  // throwable/exception
  private Throwable throwable = null;

  /**
   * Constructor with commands.
   * 
   * @param commands commands, <code>null</code> not permitted
   */
  public CardCommunicationImpl(CommandAPDU[] commands)
  {
    super();
    this.setCommands(commands);
  }

  /** {@inheritDoc} */
  @Override
  public CommandAPDU[] getCommands()
  {
    return this.commands;
  }

  /** {@inheritDoc} */
  @Override
  public int getPhase()
  {
    return this.phase;
  }

  /** {@inheritDoc} */
  @Override
  public ResponseAPDU[] getResponses()
  {
    return this.responses;
  }

  /** {@inheritDoc} */
  @Override
  public ResponseAPDU getResponse()
  {
    return this.responses != null && this.responses.length >= 1 ? this.responses[0] : null;
  }

  /** {@inheritDoc} */
  @Override
  public Throwable getThrowable()
  {
    return this.throwable;
  }

  /** {@inheritDoc} */
  @Override
  public boolean isFinished()
  {
    return this.finished;
  }

  /** {@inheritDoc} */
  @Override
  public void setCommand(CommandAPDU command)
  {
    if (command == null)
    {
      throw new IllegalArgumentException("command not permitted as null");
    }
    this.setCommands(command);
  }

  /** {@inheritDoc} */
  @Override
  public void setCommands(CommandAPDU... commands)
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
        throw new IllegalArgumentException(
                                           "command of array not permitted as incomplete command, at least 4 bytes required");
      }
    }
    this.commands = commands;
  }

  /** {@inheritDoc} */
  @Override
  public void setFinished(boolean finished)
  {
    this.finished = finished;

  }

  /** {@inheritDoc} */
  @Override
  public void setPhase(int phase)
  {
    if (phase != PHASE_POST && phase != PHASE_PREPARE)
    {
      throw new IllegalArgumentException("illegal phase");
    }
    if (this.phase == PHASE_POST && phase == PHASE_PREPARE)
    {
      throw new IllegalStateException("change from post to prepare phase not permitted");
    }
    this.phase = phase;

  }

  /** {@inheritDoc} */
  @Override
  public void setResponse(ResponseAPDU response)
  {
    if (response == null)
    {
      throw new IllegalArgumentException("response not permitted as null");
    }
    this.setResponses(response);

  }

  /** {@inheritDoc} */
  @Override
  public void setResponses(ResponseAPDU... responses)
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
          throw new IllegalArgumentException(
                                             "illegal response, response expected to possess at least 2 bytes");
        }
      }
    }
    this.responses = responses;
  }

  /** {@inheritDoc} */
  @Override
  public void setThrowable(Throwable throwable)
  {
    this.throwable = throwable;
  }

  /** {@inheritDoc} */
  @Override
  public String toString()
  {
    return super.toString()
           + "\n  Finished: "
           + this.finished
           + "\n  Phase: "
           + (this.phase == PHASE_PREPARE ? "PREPARE" : "POST")
           + "\n  Commands: "
           + (this.commands != null ? Arrays.asList(this.commands) : null)
           + "\n  Responses: "
           + (this.responses != null ? Arrays.asList(this.responses) : null)
           + "  Throwable: "
           + (this.throwable != null ? this.throwable.getClass().getName() + " / "
                                       + this.throwable.getMessage() : this.throwable);
  }

}

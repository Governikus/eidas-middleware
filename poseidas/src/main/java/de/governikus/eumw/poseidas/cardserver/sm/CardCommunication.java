/*
 * Copyright (c) 2019 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardserver.sm;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;


/**
 * Interface for smart card information exchange as combination of command(s), response and occurred
 * exceptions.
 *
 * @author Jens Wothe, jw@bos-bremen.de
 */
public interface CardCommunication
{

  /**
   * Sets occurred exception.
   * <p>
   * Notice: after set of response finished communication are to be indicated by using
   * {@link #setFinished(boolean)} accordingly.
   * </p>
   *
   * @param throwable exception, <code>null</code> permitted to clear
   */
  public void setThrowable(Throwable throwable);

  /**
   * Gets exception occurred during communication.
   *
   * @return exception, maybe <code>null</code>
   */
  public Throwable getThrowable();

  /**
   * Set single command.
   *
   * @param command, <code>null</code> or incomplete commands not permitted (at least 4 bytes)
   * @throws IllegalArgumentException if command <code>null</code>
   */
  public void setCommand(CommandAPDU command);

  /**
   * Sets multiple commands.
   *
   * @param commands, <code>null</code> or empty array not permitted, <code>null</code> or incomplete commands
   *          not permitted (at least 4 bytes)
   * @throws IllegalArgumentException if command array <code>null</code> or empty
   */
  public void setCommands(CommandAPDU... commands);

  /**
   * Gets commands.
   *
   * @return commands, not <code>null</code>, empty array possible
   */
  public CommandAPDU[] getCommands();

  /**
   * Sets response.
   * <p>
   * Notice: after set of response finished communication are to be indicated by using
   * {@link #setFinished(boolean)} accordingly.
   * </p>
   *
   * @param response response, <code>null</code> permitted to clear, response not <code>null</code> only
   *          permitted with at least 2 bytes
   * @throws IllegalArgumentException if response not <code>null</code> and response does not possess 2 bytes
   */
  public void setResponse(ResponseAPDU response);

  /**
   * Sets responses.
   * <p>
   * Notice: after set of responses finished communication are to be indicated by using
   * {@link #setFinished(boolean)} accordingly.
   * </p>
   *
   * @param responses responses, <code>null</code> permitted to clear, response not <code>null</code> only
   *          permitted with at least 2 bytes
   * @throws IllegalArgumentException if response not <code>null</code> and any single response does not
   *           possess 2 bytes
   */
  public void setResponses(ResponseAPDU... responses);

  /**
   * Gets responses.
   *
   * @return responses, maybe <code>null</code>
   */
  public ResponseAPDU[] getResponses();

  /**
   * Gets response.
   *
   * @return response, maybe <code>null</code>
   */
  public ResponseAPDU getResponse();

  /**
   * Sets communication phase.
   *
   * @param phase prepare or post phase of communication, only {@link #PHASE_PREPARE} or {@value #PHASE_POST}
   *          permitted, change from post to prepare phase are not permitted
   * @throws IllegalArgumentException if phase not valid
   * @throws IllegalStateException if phase is to changed from post to prepare phase
   * @see #PHASE_PREPARE
   * @see #PHASE_POST
   */
  public void setPhase(int phase);

  /**
   * Gets phase of communication.
   *
   * @return phase prepare or post phase of communication
   * @see #PHASE_PREPARE
   * @see #PHASE_POST
   */
  public int getPhase();

  /**
   * Constants of phase prepare - before layer processing.
   *
   * @see #getPhase()
   */
  public static int PHASE_PREPARE = 0;

  /**
   * Constants of phase post - after layer processing or on processing error.
   *
   * @see #getPhase()
   */
  public static int PHASE_POST = 1;

  /**
   * Ends or (re-)open communication.
   *
   * @param finished <code>true</code> for finished communication
   */
  public void setFinished(boolean finished);

  /**
   * Checks communication is finished or not.
   *
   * @return <code>true</code> if communication finished, <code>false</code> otherwise
   */
  public boolean isFinished();

}

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


/**
 * Interface for smart card information exchange as combination of command(s), response and occurred exceptions.
 *
 * @author Jens Wothe, jw@bos-bremen.de
 */
public interface CardCommunication
{

  /**
   * Sets occurred exception.
   * <p>
   * Notice: after set of response finished communication are to be indicated by using {@link #setFinished(boolean)}
   * accordingly.
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
   * Gets plaintext commands.
   * 
   * @return commands
   */
  public CommandAPDU[] getPlaintextCommands();

  /**
   * Sets encrypted commands.
   * 
   * @param commands, <code>null</code> or empty array not permitted, <code>null</code> or incomplete commands not
   *          permitted (at least 4 bytes)
   * @throws IllegalArgumentException if command array <code>null</code> or empty
   */
  public void setEncryptedCommands(CommandAPDU... commands);

  /**
   * Gets encrypted commands.
   * 
   * @return commands, <code>null</code> possible
   */
  public CommandAPDU[] getEncryptedCommands();

  /**
   * Sets encrypted responses.
   * 
   * @param responses responses, <code>null</code> permitted to clear, response not <code>null</code> only permitted
   *          with at least 2 bytes
   * @throws IllegalArgumentException if response not <code>null</code> and any single response does not possess 2 bytes
   */
  public void setEncryptedResponses(ResponseAPDU... responses);

  /**
   * Gets encrypted responses.
   * 
   * @return responses, maybe <code>null</code>
   */
  public ResponseAPDU[] getEncryptedResponses();

  /**
   * Sets plaintext responses.
   * 
   * @param responses responses, <code>null</code> permitted to clear, response not <code>null</code> only permitted
   *          with at least 2 bytes
   * @throws IllegalArgumentException if response not <code>null</code> and any single response does not possess 2 bytes
   */
  public void setPlaintextResponses(ResponseAPDU... responses);

  /**
   * Gets plaintext responses.
   * 
   * @return responses, maybe <code>null</code>
   */
  public ResponseAPDU[] getPlaintextResponses();
}

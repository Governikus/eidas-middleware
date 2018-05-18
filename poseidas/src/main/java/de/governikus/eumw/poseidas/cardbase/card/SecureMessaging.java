/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardbase.card;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;


/**
 * Interface for secure messaging implementation for enciphering command and deciphering response.
 * 
 * @author Jens Wothe, jw@bos-bremen.de
 */
public interface SecureMessaging
{

  /**
   * Encipher command using internal secure messaging key.
   * 
   * @param command command, <code>null</code> not permitted
   * @return enciphered command
   * @throws IllegalArgumentException if command <code>null</code>
   * @throws SecureMessagingException if cryptographic step fails
   */
  public CommandAPDU encipherCommand(CommandAPDU command) throws
    SecureMessagingException;

  /**
   * Decipher response using internal secure messaging key.
   * 
   * @param response response, <code>null</code> not permitted
   * @return deciphered response
   * @throws IllegalArgumentException if response <code>null</code>
   * @throws SecureMessagingException if cryptographic step fails
   */
  public ResponseAPDU decipherResponse(ResponseAPDU response) throws
    SecureMessagingException;
}

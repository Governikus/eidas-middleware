/*
 * Copyright (c) 2019 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardbase.card;

import javax.smartcardio.CardException;


/**
 * Exception to be thrown in case Secure Messaging fails.
 *
 * @author Arne Stahlbock, ast@bos-bremen.de
 */
public class SecureMessagingException extends CardException
{

  /**
   * Code constant indicating error at card during communication.
   */
  public static final int CODE_CARD = 0x0001;

  /**
   * Code constant indicating error at software as any cryptographic error.
   */
  public static final int CODE_SOFTWARE = 0x0002;

  /**
   * Serial Version UID.
   */
  private static final long serialVersionUID = 1L;

  /**
   * Cause.
   */
  private final Throwable cause;

  // code
  private final int code;

  /**
   * Constructor.
   *
   * @param code code
   * @param message message
   * @param cause cause
   */
  public SecureMessagingException(int code, String message, Throwable cause)
  {
    super(message);
    this.code = code;
    this.cause = cause;
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public synchronized Throwable getCause()
  {
    return this.cause;
  }

  /**
   * Gets error code of smartcard or terminal.
   *
   * @return error code
   */
  public final int getCode()
  {
    return this.code;
  }
}

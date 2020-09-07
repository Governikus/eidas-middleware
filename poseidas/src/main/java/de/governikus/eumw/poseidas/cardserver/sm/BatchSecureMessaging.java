/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardserver.sm;

import de.governikus.eumw.poseidas.cardbase.card.SecureMessaging;


/**
 * Interface for {@link SecureMessaging} able to process batches of commands / responses.
 *
 * @author Jens Wothe, jw@bos-bremen.de
 * @author Arne Stahlbock, ast@bos-bremen.de
 */
public interface BatchSecureMessaging extends SecureMessaging
{

  /**
   * Enciphers communication to smart card.
   * <p>
   * Notice: if any exception occurs during processing card communication is to be finished, phase is to be
   * set to {@link CardCommunication#PHASE_POST} and exception is to be stored at {@link CardCommunication} .
   * </p>
   *
   * @param cardCommunication combination of command(s), response and occurred throwable to modify command as
   *          required for some layers and storing occurred exceptions, <code>null</code> not permitted, at
   *          least one command must exist and phase must be {@link CardCommunication#PHASE_PREPARE}
   * @throws IllegalArgumentException if cardCommunication <code>null</code>
   */
  public void toCard(CardCommunication cardCommunication);

  /**
   * Deciphers communication from smart card.
   * <p>
   * Notice: if any exception occurs during access of layer card communication is to be finished and exception
   * is changed if required.
   * </p>
   *
   * @param cardCommunication combination of command(s), response and occurred throwable to modify response or
   *          throwable as required for some layers, <code>null</code> not permitted, end of processing
   *          responses or throwable must be indicated by {@link CardCommunication#isFinished()}, at least
   *          response or throwable must exist and phase must be {@link CardCommunication#PHASE_POST}
   * @throws IllegalArgumentException if cardCommunication, control or dialog <code>null</code>
   */
  public void fromCard(CardCommunication cardCommunication);
}

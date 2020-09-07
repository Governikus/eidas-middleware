/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardserver.eac.protocol;

import de.governikus.eumw.poseidas.cardbase.AssertUtil;
import de.governikus.eumw.poseidas.cardbase.ByteUtil;
import de.governikus.eumw.poseidas.cardbase.npa.InfoSelector.ChipAuthenticationData;
import de.governikus.eumw.poseidas.cardserver.sm.BatchSecureMessaging;


/**
 * Data class holding the final results of EAC required for further steps.
 *
 * @author Arne Stahlbock, ast@bos-bremen.de
 */
public class EACFinal
{

  /**
   * {@link BatchSecureMessaging} instance.
   */
  private final BatchSecureMessaging sm;

  /**
   * Bytes of EF.CardSecurity.
   */
  private final byte[] cardSecurityBytes;

  /**
   * Selected Chip Authentication parameters.
   */
  private final ChipAuthenticationData caData;

  /**
   * Ephemeral public key of card in CA version 3.
   */
  private final byte[] ephemeralCardKey;

  /**
   * Constructor.
   *
   * @param sm {@link BatchSecureMessaging} instance, <code>null</code> not permitted
   * @param cardSecurityBytes bytes of EF.CardSecurity, <code>null</code> or empty not permitted
   * @param caData selected Chip Authentication parameters, <code>null</code> not permitted
   * @param ephemeralKey ephemeral public key of card in CA version 3, <code>null</code> permitted if other
   *          version used
   * @throws IllegalArgumentException if any argument <code>null</code>
   */
  EACFinal(BatchSecureMessaging sm,
                  byte[] cardSecurityBytes,
                  ChipAuthenticationData caData,
                  byte[] ephemeralKey)
  {
    super();
    AssertUtil.notNull(sm, "secure messaging");
    AssertUtil.notNullOrEmpty(cardSecurityBytes, "bytes of EF.CardSecurity");
    AssertUtil.notNull(caData, "chip authentication data");
    this.sm = sm;
    this.cardSecurityBytes = cardSecurityBytes;
    this.caData = caData;
    this.ephemeralCardKey = ephemeralKey;
  }

  /**
   * Gets {@link BatchSecureMessaging} instance.
   *
   * @return {@link BatchSecureMessaging}
   */
  public BatchSecureMessaging getSM()
  {
    return this.sm;
  }

  /**
   * Gets bytes of EF.CardSecurity (as a copy).
   *
   * @return bytes of EF.CardSecurity
   */
  public byte[] getCardSecurityBytes()
  {
    return ByteUtil.copy(this.cardSecurityBytes);
  }

  /**
   * Gets selected Chip Authentication parameters.
   *
   * @return CA parameters
   */
  public ChipAuthenticationData getCaData()
  {
    return this.caData;
  }

  /**
   * Gets ephemeral key of card.
   *
   * @return ephemeral key of card
   */
  public byte[] getEphemeralCardKey()
  {
    return this.ephemeralCardKey;
  }
}

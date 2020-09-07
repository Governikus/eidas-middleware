/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardbase.card;

/**
 * Constants for ISO 7816 commands related to commands for smartcard.
 *
 * @author Jens Wothe, jw@bos-bremen.de
 */
public final class CommandAPDUConstants
{

  /**
   * Constant of header byte count): <code>4</code>.
   */
  public static final int COUNT_HEADER = 4;

  /**
   * Constant of maximum for LE (extended): <code>65536</code>.
   *
   * @see #SHORT_MAX_LE
   */
  public static final int EXTENDED_MAX_LE = 65536;

  /**
   * Constant of maximum for LC (short): <code>255</code>.
   *
   * @see #EXTENDED_MAX_LC
   */
  public static final int SHORT_MAX_LC = 255;

  /**
   * Constant of maximum for LE (short): <code>256</code>.
   *
   * @see #EXTENDED_MAX_LE
   */
  public static final int SHORT_MAX_LE = 256;

  /**
   * Constant of LC and LE byte count for extended length case 2, case 3 and case 4 (for case 4 only LC):
   * <code>3</code>.
   *
   * @see #COUNT_EXTENDED_LE_CASE4
   */
  public static final int COUNT_EXTENDED = 3;

  /**
   * Constructor.
   */
  private CommandAPDUConstants()
  {}

}

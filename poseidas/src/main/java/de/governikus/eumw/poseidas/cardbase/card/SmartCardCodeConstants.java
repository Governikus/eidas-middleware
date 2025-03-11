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

import lombok.experimental.UtilityClass;

/**
 * Class defines some default constants for smartcard related status codes.
 *
 * @author Jens Wothe, jw@bos-bremen.de
 */
@UtilityClass
public final class SmartCardCodeConstants
{

  /**
   * Constant for successfully processed execution without further qualification: <code>0x9000</code>.
   */
  public static final int SUCCESSFULLY_PROCESSED = 0x9000;

  /**
   * Constant indicating reading requested number of bytes could not be read as end of file is reached.
   */
  public static final int EOF_READ = 0x6282;

  /**
   * Constant indicating security status not satisfied / access not permitted: <code>0x6982</code>.
   */
  public static final int SECURITY_STATUS_NOT_SATISFIED = 0x6982;

  /**
   * Constant indicating command not allowed (can occur when reading directly without prior select):
   * <code>0x6986</code>.
   */
  public static final int COMMAND_NOT_ALLOWED = 0x6986;

  /**
   * Constant indicating file not present: <code>0x6A82</code>.
   */
  public static final int FILE_NOT_FOUND = 0x6A82;

  /**
   * Constant indicating referenced data not present: <code>0x6A88</code>.
   */
  public static final int REFERENCED_DATA_NOT_FOUND = 0x6A88;
}

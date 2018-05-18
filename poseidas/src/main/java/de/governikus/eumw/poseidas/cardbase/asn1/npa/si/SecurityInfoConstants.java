/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardbase.asn1.npa.si;

/**
 * Some general constants for multiple {@link SecurityInfo} related classes.
 * 
 * @author Jens Wothe, jw@bos-bremen.de
 */
public class SecurityInfoConstants
{

  /**
   * Constant for protocol.
   */
  static final String STRING_PROTOCOL = "\n-- protocol ";

  /**
   * Constant for version.
   */
  static final String STRING_VERSION = "\n-- version ";

  /**
   * Constant for parameter ID.
   */
  static final String STRING_PARAMETER_ID = "\n-- parameter ID ";

  /**
   * Constant for key ID.
   */
  static final String STRING_KEY_ID = "\n-- key ID ";

  /**
   * Constant for inconvertible value.
   */
  static final String MESSAGE_CAN_NOT_CONVERT_TO_STRING = "can not convert to String";

  /**
   * Constant for not given value.
   */
  static final String STRING_NOT_GIVEN = "not given";
}

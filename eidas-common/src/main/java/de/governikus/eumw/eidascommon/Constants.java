/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.eidascommon;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;


/**
 * Constants needed for communication between eID-Server and several kinds of client. <br>
 * In case you use one of the standard clients, you will not need this class.
 *
 * @author TT
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class Constants
{

  /**
   * Name of the HTML request parameter or HTML header holding the ID of the respective SAML request.
   */
  public static final String NAME_REFID = "requestID";

  /**
   * Prefix of status codes according to TR-03130 chapter 4.5 for the result major. This is taken from
   * TR-03112 eCard-API Part 1 Chapter 4.2.
   */
  private static final String EID_CODE_MAJOR_PREFIX = "http://www.bsi.bund.de/ecard/api/1.1/resultmajor";

  /**
   * Prefix of status codes according to TR-03130 chapter 4.5 for the result minor.
   */
  private static final String EID_CODE_MINOR_PREFIX = "http://www.bsi.bund.de/eid/server/2.0/resultminor";

  /**
   * major code indicating error according to TR-03112
   */
  public static final String EID_MAJOR_ERROR = EID_CODE_MAJOR_PREFIX + "#error";

  /**
   * major code indicating ok according to TR-03112
   */
  public static final String EID_MAJOR_OK = EID_CODE_MAJOR_PREFIX + "#ok";

  /**
   * minor error code indicating a schema violation.
   */
  public static final String EID_MINOR_COMMON_SCHEMA_VIOLATION = EID_CODE_MINOR_PREFIX
                                                                 + "/common#schemaViolation";

  /**
   * minor code for unspecified error
   */
  public static final String EID_MINOR_COMMON_INTERNALERROR = EID_CODE_MINOR_PREFIX + "/common#internalError";

  /**
   * minor error code indicating an invalid psk
   */
  public static final String EID_MINOR_USEID_INVALID_PSK = EID_CODE_MINOR_PREFIX + "/useID#invalidPSK";

  /**
   * minor error code when server is overloaded, and can not handle any more sessions.
   */
  public static final String EID_MINOR_USEID_TOO_MANY_OPEN_SESSIONS = EID_CODE_MINOR_PREFIX
                                                                      + "/useID#tooManyOpenSessions";

  /**
   * minor error code indicating a request with a missing argument e.g. for age verification or community
   * verification.
   */
  public static final String EID_MINOR_USEID_MISSING_ARGUMENT = EID_CODE_MINOR_PREFIX
                                                                + "/useID#missingArgument";

  /**
   * minor error code when the requests want's to read more attributes than allowed in the terminal
   * certificate.
   */
  public static final String EID_MINOR_USEID_MISSING_TERMINAL_RIGHTS = EID_CODE_MINOR_PREFIX
                                                                       + "/useID#missingTerminalRights";

  /**
   * minor error code when the result is not yet available.
   */
  public static final String EID_MINOR_GETRESULT_NO_RESULT_YET = EID_CODE_MINOR_PREFIX
                                                                 + "/getResult#noResultYet";

  /**
   * minor error code indicating an an invalid session id.
   */
  public static final String EID_MINOR_GETRESULT_INVALID_SESSION = EID_CODE_MINOR_PREFIX
                                                                   + "/getResult#invalidSession";

  /**
   * minor error code indicating an invalid request counter.
   */
  public static final String EID_MINOR_GETRESULT_INVALID_COUNTER = EID_CODE_MINOR_PREFIX
                                                                   + "/getResult#invalidCounter";

  /**
   * minor error code indicating an invalid document.
   */
  public static final String EID_MINOR_GETRESULT_INVALID_DOCUMENT = EID_CODE_MINOR_PREFIX
                                                                    + "/getResult#invalidDocument";
}

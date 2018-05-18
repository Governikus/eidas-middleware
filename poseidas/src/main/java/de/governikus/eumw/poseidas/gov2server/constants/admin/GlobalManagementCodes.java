/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.gov2server.constants.admin;

/**
 * This is the set of all error codes which may produced by the management of several Governikus modules. The
 * WebAdmin should be able to display a nice text for each messages created by one of these codes.
 * <p>
 * In a Governikus component DO NOT declare a message with the same meaning as one of these codes. However, if
 * appropriate you can and should declare codes for more specific messages.
 * 
 * @author tt
 */
public final class GlobalManagementCodes
{

  private GlobalManagementCodes()
  {
    // no instances needed
  }

  private static final String PREFIX_ERROR = "CO.msg.error.";

  private static final String PREFIX_OK = "CO.msg.ok.";

  /**
   * Something has happened as intended by the user.
   */
  public static final Code0 OK = new Code0(PREFIX_OK + "ok");

  /**
   * The uploaded file is not a certificate.
   */
  public static final Code0 EC_INVALIDCERTIFICATEDATA = new Code0(PREFIX_ERROR + "invalidcertificatedata");

  /**
   * The configuration data cannot be interpreted correctly.
   */
  public static final Code0 EC_INVALIDCONFIGURATIONDATA = new Code0(PREFIX_ERROR + "invalidConfiguration");

  /**
   * The input value is invalid.
   */
  public static final Code0 EC_INVALIDVALUE = new Code0(PREFIX_ERROR + "invalidvalue");

  /**
   * A value in the configuration is invalid and does not permit the current operation. Detail is the name of
   * the respective configuration attribute.
   */
  public static final Code1 EC_INVALIDCONFIGVALUE = new Code1(PREFIX_ERROR + "invalidConfigvalue");

  /**
   * A value in the configuration is missing - add it and save the configuration. Detail is the name of the
   * respective configuration attribute.
   */
  public static final Code1 EC_MISSINGCONFIGVALUE = new Code1(PREFIX_ERROR + "missingConfigvalue");

  /**
   * An unexpected error has occurred. Try to use more specific messages instead of this one. parameter
   * explaining message
   */
  public static final Code1 EC_UNEXPECTED_ERROR = new Code1(PREFIX_ERROR + "unexpectedError");

  /**
   * An external service on URL $0 cannot be reached. The problem is $1.
   */
  public static final Code2 EXTERNAL_SERVICE_NOT_REACHABLE = new Code2(PREFIX_ERROR + "serviceNotReachable");

  /**
   * Unspecified internal problem.
   */
  public static final Code0 INTERNAL_ERROR = new Code0(PREFIX_ERROR + "internalError");


}

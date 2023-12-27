/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.eidascommon;

import java.util.ResourceBundle;


/**
 * Codes to identify various error situations for the eID-Server. Clients (both those communicating with the respective
 * module and the receiver of the SAML response itself) should be able to display a comprehensive message for each of
 * these codes or handle the respective situation automatically. Please note that the SAML status codes are insufficient
 * to cover all specific situations in sufficient detail.
 *
 * @author TT
 */
public enum ErrorCode
{

  /**
   * Conversation finished successfully.
   */
  SUCCESS,
  /**
   * Error situation only specified by details. Do not use if there is a more appropriate value!
   */
  ERROR,
  /**
   * Unspecified error, see log file. May be returned to browser outside a SAML-response!
   */
  INTERNAL_ERROR,
  /**
   * Request specifies AssertionConsumerURL but is not signed - will be rejected. May be returned to browser outside a
   * SAML-response!
   */
  UNSIGNED_ASSERTIONCONSUMER_URL,
  /**
   * No pending SAML request for the specified requestID. May be returned to browser outside a SAML-response!
   */
  INVALID_SESSION_ID,
  /**
   * There are too many open sessions, this session will not be created.
   */
  TOO_MANY_OPEN_SESSIONS,
  /**
   * SAML requestID not specified in the subsequent request. May be returned to browser outside a SAML-response!
   */
  MISSING_REQUEST_ID,
  /**
   * SAML request was not signed correctly
   */
  SIGNATURE_CHECK_FAILED,
  /**
   * The SAML message was not signed but should be
   */
  SIGNATURE_MISSING,
  /**
   * There is a syntax error in the request so it cannot be parsed. May be returned to browser outside a SAML-response!
   */
  ILLEGAL_REQUEST_SYNTAX,
  /**
   * Authorization failed
   */
  AUTHORIZATION_FAILED,
  /**
   * Cannot get SAML response because another client action is needed first. May be returned to browser outside a
   * SAML-response!
   */
  AUTHORIZATION_UNFINISHED,
  /**
   * The SAML request does not specify one of the providers in the eID-Servers configuration. May be returned to browser
   * outside a SAML-response!
   */
  UNKNOWN_PROVIDER,
  /**
   * The configuration of the eID-Servers seems invalid. See log file of the application server.
   */
  ILLEGAL_CONFIGURATION,
  /**
   * The required client side resource cannot be accessed due to user does not give permission / PIN or so.
   */
  CANNOT_ACCESS_CREDENTIALS,
  /**
   * A certificate used for authorization is not valid.
   */
  INVALID_CERTIFICATE,
  /**
   * Cannot access this part of server in this way. May be returned to browser outside a SAML-response!
   */
  ILLEGAL_ACCESS_METHOD,
  /**
   * SOAP response from client has wrong format.
   */
  SOAP_RESPONSE_WRONG_SYNTAX,
  /**
   * accessing without https is not allowed.
   */
  UNENCRYPTED_ACCESS_NOT_ALLOWED,
  /**
   * Time restriction of SAML assertion not met
   */
  OUTDATED_ASSERTION,
  /**
   * The request was initially created for another destination.
   */
  WRONG_DESTINATION,

  /**
   * some asynchronous step finished for a session which did not expect it.
   */
  UNEXPECTED_EVENT,
  /**
   * Time restriction of SAML request not met
   */
  OUTDATED_REQUEST,
  /**
   * This request is from fare in the future.
   */
  REQUEST_FROM_FUTURE,
  /**
   * The request has an ID which is not unique among the IDs of all received requests. May be returned to browser
   * outside a SAML-response!
   */
  DUPLICATE_REQUEST_ID,
  /**
   * Some error was reported from the eID-Server.
   */
  EID_ERROR,
  /**
   * Some error was reported from the eCardAPI
   */
  ECARD_ERROR,
  /**
   * The client requested to read some attributes from the nPA which are not allowed by the CVC.
   */
  EID_MISSING_TERMINAL_RIGHTS,
  /**
   * The requests misses the argument for {0}.
   */
  EID_MISSING_ARGUMENT,
  /**
   * the password has expired and is therefore invalid
   */
  PASSWORD_EXPIRED,
  /**
   * the password has been locked because of too many failed tries
   */
  PASSWORD_LOCKED,
  /**
   * Encrypted input data cannot be decrypted - contained information will be missing
   */
  CANNOT_DECRYPT,
  /**
   * The psk is not fell formed or not long enough.
   */
  ILLEGAL_PSK,
  /**
   * The authentication client reported an error
   */
  CLIENT_ERROR,
  /**
   * The proxy count raced 0
   */
  PROXY_COUNT_EXCEEDED,
  /**
   * Non of the IdPs given in the IDPList in the SAML Request are supported.
   */
  NO_SUPPORTED_IDP,
  /**
   * Request was denied, ie citizen consent not given
   */
  REQUEST_DENIED,
  /**
   * Cancellation by user
   */
  CANCELLATION_BY_USER,
  /**
   * The id name type is not supported
   */
  INVALID_NAME_ID_TYPE;


  /**
   * prefix to make all the minor error codes look URN-like
   */
  public static final String URN_PREFIX = "urn:bos-bremen.de:SAML:minorCode:";

  private ErrorCode()
  {}

  private static ResourceBundle messages = ResourceBundle.getBundle("de.governikus.eumw.eidascommon.errorcodes");

  /**
   * Return human-readable text describing this code.
   *
   * @param details additional information to use in the text.
   */
  public String toDescription(String... details)
  {
    String result = messages.getString(super.toString());
    if (details != null)
    {
      for ( int i = 0 ; i < details.length ; i++ )
      {
        String detailMessage = details[i] == null ? "" : details[i];
        String placeholder = "{" + i + "}";
        if (result.contains(placeholder))
        {
          result = result.replace(placeholder, detailMessage);
        }
        else if (!detailMessage.isBlank())
        {
          result += " / " + detailMessage;
        }
      }
    }
    return result;
  }
}

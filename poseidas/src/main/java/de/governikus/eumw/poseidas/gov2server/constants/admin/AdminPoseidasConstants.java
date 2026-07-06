/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.gov2server.constants.admin;

import java.util.Collection;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;


/**
 * Definition of all constants needed to access the MBean layer of the identity manger. Do not define these constants
 * elsewhere. Do not use String literals instead of these constants. <br>
 *
 * @author hme
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class AdminPoseidasConstants
{

  /**
   * Boolean if the client is public Type: Boolean
   */
  public static final String VALUE_IS_PUBLIC_CLIENT = "isPublicClient";

  /**
   * URL to the subject's web page.<br>
   * Type: String
   */
  public static final String VALUE_PERMISSION_DATA_SUBJECT_URL = "SubjectUrl";

  /**
   * Name of the issuer.<br>
   * Type: String
   */
  public static final String VALUE_PERMISSION_DATA_ISSUER_NAME = "IssuerName";

  /**
   * Terms of use including contact address of subject and Datenschutzbehörde in plain text.<br>
   * Type: String
   */
  public static final String VALUE_PERMISSION_DATA_TERMS_OF_USAGE_PLAIN_TEXT = "TermsOfUsagePlainText";

  /**
   * Return the expiration data of the stored CVC.<br>
   * Type: Date
   */
  public static final String VALUE_PERMISSION_DATA_EXPIRATION_DATE = "ExpirationDate";

  /**
   * Subject name.<br>
   * Type: String
   */
  public static final String VALUE_PERMISSION_DATA_SUBJECT_NAME = "SubjectName";

  /**
   * Key in CVC info map: holder reference as stored in CVC. Type: String
   */
  public static final String VALUE_PERMISSION_DATA_HOLDERREFERENCE = "holderReference";


  /**
   * Key in CVC info map: reference to the certificate authority stored in CVC. Type: String
   */
  public static final String VALUE_PERMISSION_DATA_CA_REFERENCE = "caReference";


  /**
   * URL to the issuer web page.<br>
   * Type: String
   */
  public static final String VALUE_PERMISSION_DATA_ISSUER_URL = "IssuerUrl";

  /**
   * Return the issuing data of the stored CVC.<br>
   * Type: Date
   */
  public static final String VALUE_PERMISSION_DATA_EFFECTIVE_DATE = "EffectiveDate";

  /**
   * Contains a {@link Collection} of error messages in case an error occurred<br>
   * Type: {@link Collection} of ManagementMessage
   */
  public static final String VALUE_PERMISSION_DATA_ERROR_MESSAGE = "errorMessage";
}

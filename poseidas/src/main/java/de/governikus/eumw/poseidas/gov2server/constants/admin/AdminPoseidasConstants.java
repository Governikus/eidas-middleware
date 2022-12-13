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

import javax.management.MalformedObjectNameException;
import javax.management.ObjectName;

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
   * Unique name of poseidas component
   */
  private static final String APPLICATION_NAME = "poseidas";

  /**
   * Object name for the permission data handling MBean.
   */
  public static final ObjectName OBJ_PERMISSION_DATA_HANDLING = getObjectName(APPLICATION_NAME,
                                                                              "service",
                                                                              "permissisonDataHandling");

  /**
   * Terms of use including contact address of subject and Datenschutzbehörde html formated. <br>
   * Type: String
   */
  public static final String VALUE_PERMISSION_DATA_TERMS_OF_USAGE_HTML = "TermsOfUsageHTML";

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
   * Key in CVC info map: the hash of the public sector key stored in CVC. Type: String
   */
  public static final String VALUE_PERMISSION_DATA_SECTOR_PUBLIC_KEY_HASH = "sectorPublicKeyHash";

  /**
   * Key in CVC info map: reference to the certificate authority stored in CVC. Type: String
   */
  public static final String VALUE_PERMISSION_DATA_CA_REFERENCE = "caReference";

  /**
   * Returns list of fields allowed to read out.<br>
   * Type: List<String>
   */
  public static final String VALUE_PERMISSION_DATA_ALLOWED_DATA_FIELDS = "AllowedDataFields";

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
   * Return a list with the hashes of the communication certificates of the certificate description<br>
   * Type: List<String>
   */
  public static final String VALUE_PERMISSION_DATA_COMMUNICATION_CERTS_HASHES = "CommunicationCertHashes";

  /**
   * Returns the redirect URL configured in the CVC<br>
   * Type: String
   */
  public static final String VALUE_PERMISSION_DATA_REDIRECT_URL = "RedirectURL";

  /**
   * The number of entries in the blacklist.<br>
   * Type: Long
   */
  public static final String VALUE_PERMISSION_DATA_BLACKLIST_ENTRIES = "blacklistEntries";

  /**
   * Contains a {@link Collection} of error messages in case an error occurred<br>
   * Type: {@link Collection} of ManagementMessage
   */
  public static final String VALUE_PERMISSION_DATA_ERROR_MESSAGE = "errorMessage";

  /**
   * Return the pending certificate request as base64<br>
   * Type: String
   */
  public static final String VALUE_PERMISSION_DATA_PENDING_CERT_REQUEST = "pendingCertRequest";

  /**
   * Return the date of the certificate request<br>
   * Type: Date
   */
  public static final String VALUE_PERMISSION_DATA_PENDING_CERT_REQUEST_DATE = "pendingCertRequestDate";

  /**
   * Return the status of the certificate request<br>
   * Type: String
   */
  public static final String VALUE_PERMISSION_DATA_PENDING_CERT_REQUEST_STATUS = "pendingCertRequestStatus";

  /**
   * Return the message ID of the certificate request<br>
   * Type: String
   */
  public static final String VALUE_PERMISSION_DATA_PENDING_CERT_REQUEST_MESSAGE_ID = "pendingCertRequestMessageId";

  /**
   * Returns the message digest used for signing the CVC<br>
   * Type: MessageDigest
   */
  public static final String VALUE_PERMISSION_DATA_MESSAGE_DIGEST = "messageDigest";

  /**
   * Returns the date of the last master list renewal<br>
   * Type: java.util.Date
   */
  public static final String VALUE_PERMISSION_DATA_MASTER_LIST_DATE = "masterListStoreDate";

  /**
   * Returns the date of the last defect list renewal<br>
   * Type: java.util.Date
   */
  public static final String VALUE_PERMISSION_DATA_DEFECT_LIST_DATE = "defectListStoreDate";

  /**
   * Returns the date of the last black list renewal<br>
   * Type: java.util.Date
   */
  public static final String VALUE_PERMISSION_DATA_BLACK_LIST_DATE = "blackListStoreDate";

  private static ObjectName getObjectName(String domain, String key, String value)
  {
    try
    {
      return ObjectName.getInstance(domain, key, value);
    }
    catch (MalformedObjectNameException e)
    {
      throw new RuntimeException("can not create ObjectName", e);
    }
  }
}

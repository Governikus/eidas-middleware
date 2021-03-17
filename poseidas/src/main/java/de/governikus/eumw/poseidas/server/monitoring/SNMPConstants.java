/*
 * Copyright (c) 2021 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.monitoring;

import java.util.Collections;
import java.util.SortedSet;
import java.util.TreeSet;

import org.snmp4j.smi.OID;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;


/**
 * Class for SNMP constants like OIDs
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class SNMPConstants
{

  private static final String GOVERNIKUS_OID = "1.3.6.1.4.1.28939.";

  private static final String EUMW_PREFIX = GOVERNIKUS_OID + "3.";

  private static final String GET_PREFIX = EUMW_PREFIX + "1.";

  private static final String TRAP_PREFIX = EUMW_PREFIX + "2.";

  private static final String GLOBAL_PREFIX = GET_PREFIX + "1.";

  public static final String PROVIDER_SPECIFIC_PREFIX = GET_PREFIX + "2.1.";

  private static final String CVC_PREFIX = "1.";

  private static final String BLACKLIST_PREFIX = "2.";

  private static final String MASTERLIST_PREFIX = "3.";

  private static final String DEFECTLIST_PREFIX = "4.";

  private static final String CRL_PREFIX = "5.";

  private static final String RSC_PREFIX = "6.";

  private static final String TRAP_TYPE_PREFIX = TRAP_PREFIX + "10.";

  // sorted get OIDs used for GET NEXT
  public static final SortedSet<OID> SORTED_OIDS;

  // provider specific
  public static final int PROVIDER_NAME = 1;

  public static final int CVC_PRESENT = 11;

  public static final int CVC_VALID_UNTIL = 12;

  public static final int CVC_SUBJECT_URL = 13;

  public static final int CVC_TLS_CERTIFICATE_LINK_STATUS = 14;

  public static final int CVC_TLS_CERTIFICATE_VALID = 15;

  public static final int BLACKLIST_LIST_AVAILABLE = 21;

  public static final int BLACKLIST_LAST_SUCCESSFUL_RETRIEVAL = 22;

  public static final int BLACKLIST_DVCA_AVAILABILITY = 23;

  public static final int MASTERLIST_LIST_AVAILABLE = 31;

  public static final int MASTERLIST_LAST_SUCCESSFUL_RETRIEVAL = 32;

  public static final int MASTERLIST_DVCA_AVAILABILITY = 33;

  public static final int DEFECTLIST_LIST_AVAILABLE = 41;

  public static final int DEFECTLIST_LAST_SUCCESSFUL_RETRIEVAL = 42;

  public static final int DEFECTLIST_DVCA_AVAILABILITY = 43;

  public static final int RSC_PENDING_AVAILABLE = 61;

  public static final int RSC_CURRENT_CERTIFICATE_VALID_UNTIL = 62;

  /* Status for RSC set to current */
  public static final int RSC_SET_CURRENT = 0;

  public static final int RSC_NO_PENDING = 1;

  public static final int RSC_NO_REFID = 2;


  // status for list retrievals
  public static final int LIST_RENEWED = 0;

  public static final int LIST_NOT_RECEIVED = 1;

  public static final int LIST_SIGNATURE_CHECK_FAILED = 2;

  public static final int LIST_PROCESSING_ERROR = 3;

  static
  {
    SortedSet<OID> temp = new TreeSet<>();
    for ( GetOID g : GetOID.values() )
    {
      temp.add(g.toSNMPOid());
    }
    SORTED_OIDS = Collections.unmodifiableSortedSet(temp);
  }

  /**
   * Enumeration of Trap OIDs.
   */
  @AllArgsConstructor(access = AccessLevel.PRIVATE)
  public enum TrapOID
  {
    // types:
    TRAP_TYPE_MESSAGE(TRAP_TYPE_PREFIX + "1"),
    TRAP_TYPE_INT(TRAP_TYPE_PREFIX + "2"),
    TRAP_TYPE_LONG(TRAP_TYPE_PREFIX + "3"),

    // CVC related OIDs:
    CVC_TRAP_LAST_RENEWAL_STATUS(TRAP_PREFIX + CVC_PREFIX + "1"),

    // Blacklist management related OIDs:
    BLACKLIST_TRAP_LAST_RENEWAL_STATUS(TRAP_PREFIX + BLACKLIST_PREFIX + "1"),
    BLACKLIST_TRAP_LAST_RENEWAL_PROCESSING_DURATION(TRAP_PREFIX + BLACKLIST_PREFIX + "2"),

    // Masterlist management related OIDs:
    MASTERLIST_TRAP_LAST_RENEWAL_STATUS(TRAP_PREFIX + MASTERLIST_PREFIX + "1"),
    MASTERLIST_TRAP_LAST_RENEWAL_PROCESSING_DURATION(TRAP_PREFIX + MASTERLIST_PREFIX + "2"),

    // Defectlist management related OIDs:
    DEFECTLIST_TRAP_LAST_RENEWAL_STATUS(TRAP_PREFIX + DEFECTLIST_PREFIX + "1"),
    DEFECTLIST_TRAP_LAST_RENEWAL_PROCESSING_DURATION(TRAP_PREFIX + DEFECTLIST_PREFIX + "2"),

    // CRL related OIDs:
    CRL_TRAP_LAST_RENEWAL_STATUS(TRAP_PREFIX + CRL_PREFIX + "1"),

    // RSC related OIDs:
    RSC_TRAP_CHANGE_TO_CURRENT_RSC(TRAP_PREFIX + RSC_PREFIX + "1"),
    RSC_TRAP_NEW_PENDING_CERTIFICATE(TRAP_PREFIX + RSC_PREFIX + "2");

    @Getter
    private String value;
  }

  /**
   * Enumeration of Get OIDs.
   */
  @AllArgsConstructor(access = AccessLevel.PRIVATE)
  public enum GetOID
  {
    // global
    CRL_GET_AVAILABLE(GLOBAL_PREFIX + CRL_PREFIX + "1"),
    CRL_GET_LAST_SUCCESSFUL_RETRIEVAL(GLOBAL_PREFIX + CRL_PREFIX + "2"),

    GET_TLS_CERTIFICATE_VALID(GLOBAL_PREFIX + "11"),

    // provider specific
    // please note it is important for the GET NEXT implementation that PROVIDER_NAME_GET always remains the first
    // provider specific OID
    PROVIDER_NAME_GET(PROVIDER_SPECIFIC_PREFIX + PROVIDER_NAME),

    CVC_GET_PRESENT(PROVIDER_SPECIFIC_PREFIX + CVC_PRESENT),
    CVC_GET_VALID_UNTIL(PROVIDER_SPECIFIC_PREFIX + CVC_VALID_UNTIL),
    CVC_GET_SUBJECT_URL(PROVIDER_SPECIFIC_PREFIX + CVC_SUBJECT_URL),
    CVC_GET_TLS_CERTIFICATE_LINK_STATUS(PROVIDER_SPECIFIC_PREFIX + CVC_TLS_CERTIFICATE_LINK_STATUS),


    BLACKLIST_GET_LIST_AVAILABLE(PROVIDER_SPECIFIC_PREFIX + BLACKLIST_LIST_AVAILABLE),
    BLACKLIST_GET_LAST_SUCCESSFUL_RETRIEVAL(PROVIDER_SPECIFIC_PREFIX + BLACKLIST_LAST_SUCCESSFUL_RETRIEVAL),
    BLACKLIST_GET_DVCA_AVAILABILITY(PROVIDER_SPECIFIC_PREFIX + BLACKLIST_DVCA_AVAILABILITY),

    MASTERLIST_GET_LIST_AVAILABLE(PROVIDER_SPECIFIC_PREFIX + MASTERLIST_LIST_AVAILABLE),
    MASTERLIST_GET_LAST_SUCCESSFUL_RETRIEVAL(PROVIDER_SPECIFIC_PREFIX + MASTERLIST_LAST_SUCCESSFUL_RETRIEVAL),
    MASTERLIST_GET_DVCA_AVAILABILITY(PROVIDER_SPECIFIC_PREFIX + MASTERLIST_DVCA_AVAILABILITY),

    DEFECTLIST_GET_LIST_AVAILABLE(PROVIDER_SPECIFIC_PREFIX + DEFECTLIST_LIST_AVAILABLE),
    DEFECTLIST_GET_LAST_SUCCESSFUL_RETRIEVAL(PROVIDER_SPECIFIC_PREFIX + DEFECTLIST_LAST_SUCCESSFUL_RETRIEVAL),
    DEFECTLIST_GET_DVCA_AVAILABILITY(PROVIDER_SPECIFIC_PREFIX + DEFECTLIST_DVCA_AVAILABILITY),

    RSC_GET_PENDING_AVAILABLE(PROVIDER_SPECIFIC_PREFIX + RSC_PENDING_AVAILABLE),
    RSC_GET_CURRENT_CERTIFICATE_VALID_UNTIL(PROVIDER_SPECIFIC_PREFIX + RSC_CURRENT_CERTIFICATE_VALID_UNTIL);

    @Getter
    private String value;

    /**
     * If an {@link TrapOID} matches the beginning of @param value it's returned.
     *
     * @param value An oid
     * @return The matching {@link TrapOID} or throw {@link IllegalArgumentException}
     */
    public static GetOID getOID(String value)
    {
      for ( GetOID v : values() )
      {
        if (value != null && value.startsWith(v.value))
        {
          return v;
        }
      }
      throw new IllegalArgumentException("No matching OID: " + value);
    }

    /**
     * Gets the OID as org.snmp4j.smi.OID.
     * 
     * @return
     */
    public OID toSNMPOid()
    {
      return new OID(value);
    }
  }
}

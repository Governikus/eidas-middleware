/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.idprovider.accounting;

/**
 * Class to send SNMP traps
 *
 * @author tautenhahn
 */
public final class SNMPDelegate
{

  private static final String BOS_OID = "1.3.6.1.4.1.28939";

  private static final String AS_PREFIX = BOS_OID + ".2.5.";

  public static final String CERT_RENEWAL_SHUTDOWN = "Application server shuts down, CVC renewal will not be done next time.";

  public static final String CERT_RENEWAL_FAILED = "CVC renewal failed, CVC is not renewed.";

  public static final String MASTERLIST_RENEWAL_FAILED = "Master list not obtained, will continue using old one.";

  public static final String MASTERLIST_SIGNATURE_WRONG = "Obtained master list with wrong signature, will continue using old one.";

  public static final String DEFECTLIST_RENEWAL_FAILED = "Defect list not obtained, will continue using old one.";

  public static final String DEFECTLIST_SIGNATURE_WRONG = "Obtained defect list with wrong signature, will continue using old one.";

  public static final String CANNOT_RESCHEDULE_TIMERS = "Problem re-scheduling timers.";

  public static final String BLACKLIST_RENEWAL_FAILED = "Black list not obtained, will continue using old one.";

  public static final String CERT_RENEWAL_ASYNCHRONOUS = "poseidas has requested the renewal of an expired certificate. The administrator should get into contact with the BerCA about that process.";

  public static final String PUBLIC_SECTOR_KEY_REQUEST_FAILED = "The Request for the public sector key failed";

  public static final String HSM_NOT_AVAILABLE = "HSM not available - cannot make certificate renewals.";

  private static SNMPDelegate instance = new SNMPDelegate();

  /**
   * singleton getter
   */
  public static SNMPDelegate getInstance()
  {
    return instance;
  }

  /**
   * Enumeration of OIDs to send SMNP traps for
   */
  public enum OID
  {
    /**
     * Server running. Observers should check that this event happens about every half hour.
     */
    HEARTBEAT(AS_PREFIX + "0"),

    /**
     * application server shuts down, CVC renewal will not be done next time
     */
    CERT_RENEWAL_SHUTDOWN(AS_PREFIX + "1.1"),
    /**
     * CVC renewal failed, CVC is not renewed
     */
    CERT_RENEWAL_FAILED(AS_PREFIX + "1.2"),
    /**
     * Master list not obtained, will continue using old one
     */
    MASTERLIST_RENEWAL_FAILED(AS_PREFIX + "1.3.0"),
    /**
     * Obtained master list with wrong signature, will continue using old one
     */
    MASTERLIST_SIGNATURE_WRONG(AS_PREFIX + "1.3.1"),
    /**
     * Defect list not obtained, will continue using old one
     */
    DEFECTLIST_RENEWAL_FAILED(AS_PREFIX + "1.4.0"),
    /**
     * Obtained defect list with wrong signature, will continue using old one
     */
    DEFECTLIST_SIGNATURE_WRONG(AS_PREFIX + "1.4.1"),
    /**
     * Problem re-scheduling timers
     */
    CANNOT_RESCHEDULE_TIMERS(AS_PREFIX + "1.5"),
    /**
     * Defect list not obtained, will continue using old one
     */
    BLACKLIST_RENEWAL_FAILED(AS_PREFIX + "1.6.0"),
    /**
     * Obtained defect list with wrong signature, will continue using old one
     */
    BLACKLIST_SIGNATURE_WRONG(AS_PREFIX + "1.6.1"),
    /**
     * poseidas has requested the renewal of an expired certificate. The administrator should get into contact
     * with the BerCA about that process.
     */
    CERT_RENEWAL_ASYNCHRONOUS(AS_PREFIX + "1.7"),
    /**
     * The Request for the public sector key failed
     */
    PUBLIC_SECTOR_KEY_REQUEST_FAILED(AS_PREFIX + "1.8"),
    /**
     * HSM not available - cannot make certificate renewals
     */
    HSM_NOT_AVAILABLE(AS_PREFIX + "2.0");

    private String value;

    private OID(String value)
    {
      this.value = value;
    }

    /**
     * Return the OID as String
     */
    public String getValue()
    {
      return value;
    }
  }

  private SNMPDelegate()
  {
    // nothing to do
  }

  /**
   * Send an SNMP trap
   *
   * @param oid
   * @param message optional
   */
  public void sendSNMPTrap(OID oid, String... message)
  {
    StringBuilder text = new StringBuilder();
    for ( String msg : message )
    {
      text.append(msg).append(' ');
    }

    SNMPTrapSender.sendNotification(oid.getValue(), text.toString().substring(0, text.length() - 1));
  }
}

/*
 * Copyright (c) 2022 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.config.model;

import static de.governikus.eumw.poseidas.cardserver.certrequest.CvcRequestGenerator.increaseCHR;
import static de.governikus.eumw.poseidas.server.pki.CVCRequestHandler.getHolderReferenceStringOfPendingRequest;

import java.io.IOException;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Calendar;
import java.util.Date;
import java.util.Locale;
import java.util.Map;

import de.governikus.eumw.config.ServiceProviderType;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.ECCVCertificate;
import de.governikus.eumw.poseidas.gov2server.constants.admin.AdminPoseidasConstants;
import de.governikus.eumw.poseidas.server.pki.PendingCertificateRequest;
import de.governikus.eumw.poseidas.server.pki.TerminalPermission;
import de.governikus.eumw.poseidas.server.pki.TerminalPermissionAOBean;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;


/**
 * This class represents a single service provider entity. It provides methods for getting entity details
 *
 * @author bpr
 */
@Slf4j
public class ServiceProviderDetails
{

  private final ServiceProviderType entry;

  private final Map<String, Object> info;

  private final String entityID;

  private final TerminalPermissionAOBean terminalPermissionAOBean;

  @Getter
  private final ServiceProviderStatus serviceProviderStatus;

  public ServiceProviderDetails(ServiceProviderType entry,
                                Map<String, Object> info,
                                ServiceProviderStatus serviceProviderStatus,
                                TerminalPermissionAOBean terminalPermissionAOBean)
  {
    this.entry = entry;
    entityID = entry.getName();
    this.info = info;
    this.serviceProviderStatus = serviceProviderStatus;
    this.terminalPermissionAOBean = terminalPermissionAOBean;
  }


  /***
   * Get the entityID
   *
   * @return entityID as string.
   */
  public String getEntityID()
  {
    return entityID;
  }


  /***
   * Get the CVCRefID from the CVC
   *
   * @return CAR as string.
   */
  public String getCVCRefID()
  {
    return entry.getCVCRefID();
  }

  /***
   * Get the CHR from the CVC
   *
   * @return CHR as string.
   */
  public String getCHR()
  {
    try
    {
      return (String)info.get(AdminPoseidasConstants.VALUE_PERMISSION_DATA_HOLDERREFERENCE);
    }
    catch (NullPointerException e)
    {
      return "";
    }
  }

  /***
   * Get the subject name from the CVC
   *
   * @return subject name as string.
   */
  public String getSubjectName()
  {
    try
    {
      return (String)info.get(AdminPoseidasConstants.VALUE_PERMISSION_DATA_SUBJECT_NAME);
    }
    catch (NullPointerException e)
    {
      return "";
    }
  }

  /***
   * Get the subject URL from the CVC
   *
   * @return subject URL as string.
   */
  public String getSubjectURL()
  {
    try
    {
      return (String)info.get(AdminPoseidasConstants.VALUE_PERMISSION_DATA_SUBJECT_URL);
    }
    catch (NullPointerException e)
    {
      return "";
    }
  }

  /***
   * Get the CAR from the CVC
   *
   * @return CAR as string.
   */
  public String getCAR()
  {
    try
    {
      return (String)info.get(AdminPoseidasConstants.VALUE_PERMISSION_DATA_CA_REFERENCE);
    }
    catch (NullPointerException e)
    {
      return "";
    }
  }

  private String dateToString(Date date)
  {
    if (date == null)
    {
      return "";
    }
    String pattern = "yyyy-MM-dd";
    SimpleDateFormat simpleDateFormat = new SimpleDateFormat(pattern, Locale.ENGLISH);
    return simpleDateFormat.format(date);
  }

  /***
   * Get the date as string from when the CVC is valid
   *
   * @return Formatted date string.
   */
  public String getValidFrom()
  {
    return dateToString((Date)info.get(AdminPoseidasConstants.VALUE_PERMISSION_DATA_EFFECTIVE_DATE));
  }

  /***
   * Get the date as string until the CVC is valid
   *
   * @return Formatted date string.
   */
  public String getValidUntil()
  {
    return dateToString(getValidUntilDate());
  }

  /***
   * Checks if the CVC is expired and no RSC is given
   *
   * @return true, if the CVC is expired and no RSC is given
   */
  public boolean isExpiredNoRsc()
  {
    Date expirationDate = (Date)info.get(AdminPoseidasConstants.VALUE_PERMISSION_DATA_EXPIRATION_DATE);
    if (expirationDate == null)
    {
      return false;
    }
    return !serviceProviderStatus.isRscAnyPresent() && Instant.now().isAfter(expirationDate.toInstant());
  }

  /***
   * Checks if the CVC is expired but not more than two days and an RSC is given
   *
   * @return true, if the CVC is expired but not more than two hors and an RSC is given
   */
  public boolean isExpiredUnderTwoDaysWithRsc()
  {
    Date expirationDate = (Date)info.get(AdminPoseidasConstants.VALUE_PERMISSION_DATA_EXPIRATION_DATE);
    if (expirationDate == null)
    {
      return false;
    }
    Instant expirationDatePlusTwoDays = expirationDate.toInstant().plus(2, ChronoUnit.DAYS);
    Instant now = Instant.now();
    return serviceProviderStatus.isRscAnyPresent() && now.isAfter(expirationDate.toInstant())
           && now.isBefore(expirationDatePlusTwoDays);
  }

  /***
   * Checks if the CVC is expired more than two days and an RSC is given
   *
   * @return true, if the CVC is expired more than two hors and an RSC is given
   */
  public boolean isExpiredOverTwoDaysWithRsc()
  {
    Date expirationDate = (Date)info.get(AdminPoseidasConstants.VALUE_PERMISSION_DATA_EXPIRATION_DATE);
    if (expirationDate == null)
    {
      return false;
    }
    Instant expirationDatePlusTwoDays = expirationDate.toInstant().plus(2, ChronoUnit.DAYS);
    return serviceProviderStatus.isRscAnyPresent() && Instant.now().isAfter(expirationDatePlusTwoDays);
  }

  private Date getValidUntilDate()
  {
    // Internally this is not the expiration date but the day after the expiration date.
    // To show the correct expiration data, also knows as valid until, one day must be subtracted.
    Date date = (Date)info.get(AdminPoseidasConstants.VALUE_PERMISSION_DATA_EXPIRATION_DATE);
    if (date == null)
    {
      return null;
    }
    Calendar calendar = Calendar.getInstance();
    calendar.setTime(date);
    calendar.add(Calendar.DATE, -1);
    return calendar.getTime();
  }

  /***
   * Get the next sequence number to use in an initial request
   *
   * @return the next sequence number to use.
   */
  public Integer getSuggestedCvcNextSequence() throws IOException
  {
    TerminalPermission terminalPermission = terminalPermissionAOBean.getTerminalPermission(getCVCRefID());
    // Use sequence number stored
    if (terminalPermission.getNextCvcSequenceNumber() != null)
    {
      if (log.isTraceEnabled())
      {
        log.trace("Suggesting new sequence number for service provider {} based on last used sequence number",
                  getCVCRefID());
      }
      return terminalPermission.getNextCvcSequenceNumber();
    }

    // Try to use pending request as a hint, if last sequence number is not stored
    PendingCertificateRequest pendingRequest = terminalPermission.getPendingRequest();
    if (pendingRequest != null)
    {
      String currentHolderReference = getHolderReferenceStringOfPendingRequest(pendingRequest);
      if (currentHolderReference != null)
      {
        // If pending may be reused, suggest sequence number of pending request
        if (pendingRequest.isCanBeSentAgain())
        {
          if (log.isTraceEnabled())
          {
            log.trace("Suggesting new sequence number for service provider {} based on reusable pending request",
                      terminalPermission,
                      getCVCRefID());
          }
          return getNumberOfCHR(currentHolderReference);
        }
        if (log.isTraceEnabled())
        {
          log.trace("Suggesting new sequence number for service provider {} based on not reusable pending request",
                    terminalPermission,
                    getCVCRefID());
        }
        // If pending may not be reused, suggest increased sequence number
        return getNumberOfCHR(increaseCHR(currentHolderReference));
      }
    }

    // If no last sequence, pending request or cvc is available, suggest 1
    if (terminalPermission.getCvc() == null)
    {
      if (log.isTraceEnabled())
      {
        log.trace("Suggesting new sequence number for service provider {} based on no hints",
                  terminalPermission,
                  getCVCRefID());
      }
      return 1;
    }

    if (log.isTraceEnabled())
    {
      log.trace("Suggesting new sequence number for service provider {} based on current cvc",
                terminalPermission,
                getCVCRefID());
    }

    // If no last sequence or pending request but cvc is available, suggest increased cvc sequence number
    return getNumberOfCHR(increaseCHR(new ECCVCertificate(terminalPermission.getCvc()).getHolderReferenceString()));
  }

  public static Integer getNumberOfCHR(String currentHolderReference)
  {
    if (currentHolderReference == null)
    {
      return null;
    }
    // TODO: Consider support for alphanumeric sequence numbers if the eumw supports these.
    return Integer.parseInt(currentHolderReference.substring(currentHolderReference.length() - 5));
  }


  /***
   * Get the issuer name from the CVC
   *
   * @return Issuer name as string.
   */
  public String getIssuerName()
  {
    try
    {
      return (String)info.get(AdminPoseidasConstants.VALUE_PERMISSION_DATA_ISSUER_NAME);
    }
    catch (NullPointerException e)
    {
      return "";
    }
  }

  /***
   * Get the issuer URL from the CVC
   *
   * @return Issuer URL as string.
   */
  public String getIssuerURL()
  {
    try
    {
      return (String)info.get(AdminPoseidasConstants.VALUE_PERMISSION_DATA_ISSUER_URL);
    }
    catch (NullPointerException e)
    {
      return "";
    }
  }

  /***
   * Get the redirect URL from the CVC
   *
   * @return Redirect URL as string.
   */
  public String getRedirectURL()
  {
    try
    {
      return (String)info.get(AdminPoseidasConstants.VALUE_PERMISSION_DATA_REDIRECT_URL);
    }
    catch (NullPointerException e)
    {
      return "";
    }
  }

  /***
   * Get the terms of usage from the CVC
   *
   * @return Terms of usage as plain text.
   */
  public String getTermsOfUsagePlainText()
  {
    try
    {
      return (String)info.get(AdminPoseidasConstants.VALUE_PERMISSION_DATA_TERMS_OF_USAGE_PLAIN_TEXT);
    }
    catch (NullPointerException e)
    {
      return "";
    }
  }

  /***
   * Checks if the service provider is a public client
   *
   * @return true if it's a puclic client
   */
  public boolean isPublicClient()
  {
    return (boolean)info.get(AdminPoseidasConstants.VALUE_IS_PUBLIC_CLIENT);
  }

  /***
   * Checks if the service provider is active
   *
   * @return True if the service provider is active
   */
  public boolean isEnabled()
  {
    return this.entry.isEnabled();
  }
}

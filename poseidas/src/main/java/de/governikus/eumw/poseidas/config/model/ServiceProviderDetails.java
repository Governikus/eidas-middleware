/*
 * Copyright (c) 2022 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.config.model;

import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.Locale;
import java.util.Map;

import de.governikus.eumw.config.ServiceProviderType;
import de.governikus.eumw.poseidas.gov2server.constants.admin.AdminPoseidasConstants;
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

  @Getter
  private final ServiceProviderStatus serviceProviderStatus;

  public ServiceProviderDetails(ServiceProviderType entry,
                                Map<String, Object> info,
                                ServiceProviderStatus serviceProviderStatus)
  {
    this.entry = entry;
    entityID = entry.getName();
    this.info = info;
    this.serviceProviderStatus = serviceProviderStatus;
  }

  public String getEntityID()
  {
    return entityID;
  }

  public String getCVCRefID()
  {
    return entry.getCVCRefID();
  }

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
      return null;
    }
    String pattern = "yyyy-MM-dd";
    SimpleDateFormat simpleDateFormat = new SimpleDateFormat(pattern, Locale.ENGLISH);
    return simpleDateFormat.format(date);
  }

  public String getValidFrom()
  {
    try
    {
      return dateToString((Date)info.get(AdminPoseidasConstants.VALUE_PERMISSION_DATA_EFFECTIVE_DATE));
    }
    catch (NullPointerException e)
    {
      return "";
    }
  }

  public String getValidUntil()
  {
    try
    {
      // Internally this is not the expiration date but the day after the expiration date.
      // To show the correct expiration data, also knows as valid until, one day must be subtracted.
      Date invalidOn = (Date)info.get(AdminPoseidasConstants.VALUE_PERMISSION_DATA_EXPIRATION_DATE);
      Calendar calendar = Calendar.getInstance();
      calendar.setTime(invalidOn);
      calendar.add(Calendar.HOUR, -24);
      return dateToString(calendar.getTime());
    }
    catch (NullPointerException e)
    {
      return "";
    }
  }

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

  public String getTermsOfUsagePlanText()
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

  public boolean isPublicClient()
  {
    return (boolean)info.get(AdminPoseidasConstants.VALUE_IS_PUBLIC_CLIENT);
  }

  public boolean isEnabled()
  {
    return this.entry.isEnabled();
  }
}

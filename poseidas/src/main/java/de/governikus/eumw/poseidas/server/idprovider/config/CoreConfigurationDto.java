/*
 * Copyright (c) 2019 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.idprovider.config;

import java.io.Reader;
import java.util.Calendar;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;

import de.governikus.eumw.poseidas.config.schema.CoreConfigurationType;
import de.governikus.eumw.poseidas.config.schema.ObjectFactory;
import de.governikus.eumw.poseidas.config.schema.ServiceProviderType;
import de.governikus.eumw.poseidas.config.schema.TimerConfigurationType;
import de.governikus.eumw.poseidas.config.schema.TimerType;


/**
 * Wrapper for CoreConfigurationType to make generic MBean look better.
 *
 * @author tt
 */
public class CoreConfigurationDto extends AbstractConfigDto<CoreConfigurationType>
{

  private Map<String, ServiceProviderDto> serviceProviders;

  /**
   * For creation you need an object to wrap.
   *
   * @param jaxBConfig
   */
  CoreConfigurationDto(CoreConfigurationType jaxBConfig)
  {
    super(jaxBConfig);
  }

  @Override
  protected void setJaxbConfig(CoreConfigurationType jaxBConfig)
  {
    this.jaxbConfig = jaxBConfig;

    serviceProviders = new TreeMap<>();
    for ( ServiceProviderType provider : jaxbConfig.getServiceProvider() )
    {
      serviceProviders.put(provider.getEntityID(), new ServiceProviderDto(provider));
    }
    if (jaxbConfig.getTimerConfiguration() == null)
    {
      TimerConfigurationType timerConf = new TimerConfigurationType();
      jaxbConfig.setTimerConfiguration(timerConf);
    }

    TimerConfigurationType timerConf = jaxbConfig.getTimerConfiguration();
    if (timerConf.getBlacklistRenewal() == null)
    {
      timerConf.setBlacklistRenewal(new TimerType());
      timerConf.getBlacklistRenewal().setLength(15);
      timerConf.getBlacklistRenewal().setUnit(Calendar.MINUTE);
    }
    if (timerConf.getCertRenewal() == null)
    {
      timerConf.setCertRenewal(new TimerType());
      timerConf.getCertRenewal().setLength(1);
      timerConf.getCertRenewal().setUnit(Calendar.HOUR_OF_DAY);
    }
    if (timerConf.getMasterAndDefectListRenewal() == null)
    {
      timerConf.setMasterAndDefectListRenewal(new TimerType());
      timerConf.getMasterAndDefectListRenewal().setLength(1);
      timerConf.getMasterAndDefectListRenewal().setUnit(Calendar.DAY_OF_MONTH);
    }

    if (jaxbConfig.getSessionMaxPendingRequests() == 0)
    {
      jaxbConfig.setSessionMaxPendingRequests(500);
    }
  }

  /**
   * Create new object from XML data
   *
   * @param reader
   * @throws JAXBException
   */
  @SuppressWarnings("unchecked")
  static CoreConfigurationDto readFrom(Reader reader) throws JAXBException
  {
    JAXBContext context = JAXBContext.newInstance(ObjectFactory.class);
    Object po = context.createUnmarshaller().unmarshal(reader);
    CoreConfigurationType parsed = null;
    if (po instanceof CoreConfigurationType)
    {
      parsed = (CoreConfigurationType)po;
    }
    else
    {
      parsed = ((JAXBElement<CoreConfigurationType>)po).getValue();
    }
    return new CoreConfigurationDto(parsed);
  }

  @Override
  public CoreConfigurationType getJaxbConfig()
  {
    jaxbConfig.getServiceProvider().clear();
    for ( ServiceProviderDto provider : serviceProviders.values() )
    {
      jaxbConfig.getServiceProvider().add(provider.getJaxbConfig());
    }
    return jaxbConfig;
  }

  /**
   * Return the URL of the SSO service. Note that the URL of the web service is different!
   */
  public String getServerUrl()
  {
    return jaxbConfig.getServerUrl();
  }

  /**
   * Set the URL of the SSO service.
   */
  public void setServerUrl(String serverUrl)
  {
    jaxbConfig.setServerUrl(serverUrl);
  }

  /**
   * Return the set of serviceProviders addressed by entityID
   */
  public Map<String, ServiceProviderDto> getServiceProvider()
  {
    return serviceProviders;
  }

  /**
   * Return whether the session manager should store the sessions in database (alternative is memory).
   */
  public boolean isSessionManagerUsesDatabase()
  {
    return jaxbConfig.isSessionManagerUsesDatabase();
  }

  /**
   * Impose whether the session manager should store the sessions in database (alternative is memory).
   */
  public void setSessionManagerUsesDatabase(boolean value)
  {
    jaxbConfig.setSessionManagerUsesDatabase(value);
  }

  /**
   * Return the maximum number of sessions to be stored in the session store.
   */
  public int getSessionMaxPendingRequests()
  {
    return jaxbConfig.getSessionMaxPendingRequests();
  }

  /**
   * Set the maximum number of sessions to be stored in the session store.
   */
  public void setSessionMaxPendingRequests(int value)
  {
    jaxbConfig.setSessionMaxPendingRequests(value);
  }

  /**
   * Return the configuration for the renewal timer intervals.
   */
  public TimerConfigurationType getTimerConfiguration()
  {
    return jaxbConfig.getTimerConfiguration();
  }

  public Set<String> getAllowedDocumentTypes()
  {
    Set<String> result = new HashSet<>();
    result.add("A");
    result.add("ID");
    String typesString = jaxbConfig.getAllowedDocumentTypes();
    if (typesString != null)
    {
      for ( String type : typesString.split(",") )
      {
        result.add(type.trim());
      }
    }
    return result;
  }
}

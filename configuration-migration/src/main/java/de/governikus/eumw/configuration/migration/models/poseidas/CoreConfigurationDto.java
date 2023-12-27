/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.configuration.migration.models.poseidas;

import java.io.Reader;
import java.util.Calendar;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;

import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBElement;
import jakarta.xml.bind.JAXBException;

import de.governikus.eumw.poseidas.config.schema.CoreConfigurationType;
import de.governikus.eumw.poseidas.config.schema.ObjectFactory;
import de.governikus.eumw.poseidas.config.schema.ServiceProviderType;
import de.governikus.eumw.poseidas.config.schema.TimerConfigurationType;
import de.governikus.eumw.poseidas.config.schema.TimerType;
import de.governikus.eumw.poseidas.server.idprovider.exceptions.InvalidConfigurationException;


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
    if (timerConf.getCrlRenewal() == null)
    {
      timerConf.setCrlRenewal(new TimerType());
      timerConf.getCrlRenewal().setLength(12);
      timerConf.getCrlRenewal().setUnit(Calendar.HOUR_OF_DAY);
    }
    if (timerConf.getCrlCacheTime() == null)
    {
      timerConf.setCrlCacheTime(new TimerType());
      timerConf.getCrlCacheTime().setLength(24);
      timerConf.getCrlCacheTime().setUnit(Calendar.HOUR_OF_DAY);
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
  static CoreConfigurationDto readFrom(Reader reader) throws JAXBException, InvalidConfigurationException
  {
    JAXBContext context = JAXBContext.newInstance(ObjectFactory.class);
    Object po = context.createUnmarshaller().unmarshal(reader);
    CoreConfigurationType parsed;
    if (po instanceof CoreConfigurationType)
    {
      parsed = (CoreConfigurationType)po;
    }
    else
    {
      parsed = ((JAXBElement<CoreConfigurationType>)po).getValue();
    }
    validateConfig(parsed);
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
   * Return the set of serviceProviders addressed by entityID
   */
  public Map<String, ServiceProviderDto> getServiceProvider()
  {
    return serviceProviders;
  }

  /**
   * Return the configuration for the renewal timer intervals.
   */
  public TimerConfigurationType getTimerConfiguration()
  {
    return jaxbConfig.getTimerConfiguration();
  }

  /**
   * Get the allowed documents types. Default types are A, ID and UB
   *
   * @return the allowed documents type
   */
  public Set<String> getAllowedDocumentTypes()
  {
    Set<String> result = new HashSet<>();
    result.add("A");
    result.add("ID");
    result.add("UB");
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

  private static void validateConfig(CoreConfigurationType config) throws InvalidConfigurationException
  {

    List<ServiceProviderType> serviceProviders = config.getServiceProvider();
    Set<ServiceProviderType> duplicatedServiceProviderList = new HashSet<>();
    serviceProviders.forEach(serviceProvider -> {
      if (serviceProviders.stream()
                          .filter(serviceProvider2 -> serviceProvider.getEntityID()
                                                                     .contentEquals(serviceProvider2.getEntityID()))
                          .count() > 1)
      {
        duplicatedServiceProviderList.add(serviceProvider);
      }
    });

    if (!duplicatedServiceProviderList.isEmpty())
    {
      Optional<ServiceProviderType> first = duplicatedServiceProviderList.stream().findFirst();
      throw new InvalidConfigurationException("Duplicated Service Provider Name found: "
                                              + (first.isPresent() ? first.get().getEntityID() : ""));
    }
  }
}

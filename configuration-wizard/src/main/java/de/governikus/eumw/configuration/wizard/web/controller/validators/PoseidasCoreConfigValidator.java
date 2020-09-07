/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.configuration.wizard.web.controller.validators;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.springframework.validation.BindingResult;

import de.governikus.eumw.configuration.wizard.identifier.HSMTypeIdentifier;
import de.governikus.eumw.configuration.wizard.web.model.ConfigurationForm;
import de.governikus.eumw.configuration.wizard.web.model.poseidasxml.ServiceProviderForm;


/**
 * project: eumw <br>
 * author Pascal Knueppel <br>
 * created at: 15.02.2018 - 08:36 <br>
 * <br>
 */
public class PoseidasCoreConfigValidator extends ViewValidator
{

  /**
   * {@inheritDoc}
   */
  @Override
  public void validateView(ConfigurationForm configurationForm, BindingResult bindingResult)
  {
    checkUrl("poseidasConfig.coreConfig.serverUrl",
             configurationForm.getPoseidasConfig().getCoreConfig().getServerUrl(),
             bindingResult);

    ServiceProviderForm commonServiceProvider = configurationForm.getPoseidasConfig()
                                                                 .getCommonServiceProviderData();
    checkNamedObject("poseidasConfig.commonServiceProviderData.blackListTrustAnchor",
                     commonServiceProvider.getBlackListTrustAnchor(),
                     bindingResult,
                     true);
    checkNamedObject("poseidasConfig.commonServiceProviderData.masterListTrustAnchor",
                     commonServiceProvider.getMasterListTrustAnchor(),
                     bindingResult,
                     true);
    checkNamedObject("poseidasConfig.commonServiceProviderData.sslKeysForm.serverCertificate",
                     commonServiceProvider.getSslKeysForm().getServerCertificate(),
                     bindingResult,
                     true);
    checkRadioButton("poseidasConfig.commonServiceProviderData.dvcaProvider",
                     commonServiceProvider.getDvcaProvider(),
                     bindingResult);

    if (configurationForm.getPoseidasConfig().getServiceProviders().isEmpty())
    {
      bindingResult.reject("wizard.status.validation.missing.serviceprovider",
                           "You must create at least one Service Provider.");
      return;
    }
    else
    {
      List<ServiceProviderForm> serviceProviders = configurationForm.getPoseidasConfig()
                                                                    .getServiceProviders();
      Set<ServiceProviderForm> duplicatedServiceProviderSet = new HashSet<>();
      serviceProviders.forEach(serviceProvider -> {
        if (serviceProviders.stream()
                            .filter(serviceProvider2 -> serviceProvider.getEntityID()
                                                                       .equalsIgnoreCase(serviceProvider2.getEntityID()))
                            .count() > 1
            && duplicatedServiceProviderSet.stream()
                                           .noneMatch(serviceProviderToCompare -> serviceProviderToCompare.getEntityID()
                                                                                                          .equalsIgnoreCase(serviceProvider.getEntityID())))
        {
          duplicatedServiceProviderSet.add(serviceProvider);
        }
      });
      duplicatedServiceProviderSet.forEach(serviceProvider -> bindingResult.reject("wizard.status.validation.duplicatedEntityId.serviceprovider",
                                                                                   new String[]{"\""
                                                                                                + serviceProvider.getEntityID()
                                                                                                + "\""},
                                                                                   "Every Service Provider must have an unique id (EntityID)"));
    }

    boolean defaultServiceProviderSelected = false;

    for ( ServiceProviderForm serviceProvider : configurationForm.getPoseidasConfig().getServiceProviders() )
    {

      checkNonBlankString("singleServiceProvider.entityID", serviceProvider.getEntityID(), bindingResult);

      if (!HSMTypeIdentifier.isUsingHSM(configurationForm.getApplicationProperties().getHsmType()))
      {
        checkNamedObject("poseidasConfig.serviceProvider.sslKeysForm.clientKeyForm",
                         serviceProvider.getSslKeysForm().getClientKeyForm(),
                         bindingResult,
                         false);
      }

      if (serviceProvider.isPublicServiceProvider() && defaultServiceProviderSelected)
      {
        bindingResult.reject("wizard.status.validation.incorrect.default.serviceprovider",
                             "You must select exactly one Public Service Provider");
        break;
      }
      else if (serviceProvider.isPublicServiceProvider() && !defaultServiceProviderSelected)
      {
        defaultServiceProviderSelected = true;
      }
    }
    if (!defaultServiceProviderSelected)
    {
      bindingResult.reject("wizard.status.validation.incorrect.default.serviceprovider",
                           "You must select exactly one Public Service Provider");
    }
  }
}

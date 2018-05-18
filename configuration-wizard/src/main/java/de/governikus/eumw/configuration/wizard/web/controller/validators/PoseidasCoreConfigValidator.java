/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.configuration.wizard.web.controller.validators;

import org.springframework.validation.BindingResult;

import de.governikus.eumw.configuration.wizard.web.model.ConfigurationForm;


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
    checkNonBlankString("poseidasConfig.serviceProvider.entityID",
                        configurationForm.getPoseidasConfig().getServiceProvider().getEntityID(),
                        bindingResult);
    checkNamedObject("poseidasConfig.serviceProvider.blackListTrustAnchor",
                     configurationForm.getPoseidasConfig().getServiceProvider().getBlackListTrustAnchor(),
                     bindingResult, true);
    checkNamedObject("poseidasConfig.serviceProvider.masterListTrustAnchor",
                     configurationForm.getPoseidasConfig().getServiceProvider().getMasterListTrustAnchor(),
                     bindingResult, true);
    checkNamedObject("poseidasConfig.serviceProvider.defectListTrustAnchor",
                     configurationForm.getPoseidasConfig().getServiceProvider().getDefectListTrustAnchor(),
                     bindingResult, true);
    checkNamedObject("poseidasConfig.serviceProvider.sslKeysForm.serverCertificate",
                     configurationForm.getPoseidasConfig()
                                      .getServiceProvider()
                                      .getSslKeysForm()
                                      .getServerCertificate(),
                     bindingResult, true);
    checkNamedObject("poseidasConfig.serviceProvider.sslKeysForm.clientKeyForm",
                     configurationForm.getPoseidasConfig()
                                      .getServiceProvider()
                                      .getSslKeysForm()
                                      .getClientKeyForm(),
                     bindingResult, false);
    checkRadioButton("poseidasConfig.serviceProvider.policyID",
                     configurationForm.getPoseidasConfig().getServiceProvider().getPolicyID(),
                     bindingResult);
  }
}

/*
 * Copyright (c) 2019 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.configuration.wizard.web.controller.validators;

import org.springframework.validation.BindingResult;

import de.governikus.eumw.configuration.wizard.identifier.HSMTypeIdentifier;
import de.governikus.eumw.configuration.wizard.web.model.ApplicationPropertiesForm;
import de.governikus.eumw.configuration.wizard.web.model.ConfigurationForm;


/**
 * project: eumw <br>
 * author Pascal Knueppel <br>
 * created at: 15.02.2018 - 11:43 <br>
 * <br>
 */
public class ApplicationPropertiesValidator extends ViewValidator
{

  /**
   * {@inheritDoc}
   */
  @Override
  public void validateView(ConfigurationForm configurationForm, BindingResult bindingResult)
  {
    ApplicationPropertiesForm appProperties = configurationForm.getApplicationProperties();

    checkPort("applicationProperties.serverPort", appProperties.getServerPort(), bindingResult);
    checkNamedObject("applicationProperties.serverSslKeystore",
                     appProperties.getServerSslKeystore(),
                     bindingResult,
                     false);
    checkNonBlankString("applicationProperties.datasourceUrl",
                        appProperties.getDatasourceUrl(),
                        bindingResult);
    checkNonBlankString("applicationProperties.datasourceUsername",
                        appProperties.getDatasourceUsername(),
                        bindingResult);
    checkNonBlankString("applicationProperties.datasourcePassword",
                        appProperties.getDatasourcePassword(),
                        bindingResult);
    checkNonBlankString("applicationProperties.adminUsername",
                        appProperties.getAdminUsername(),
                        bindingResult);
    checkNonBlankString("applicationProperties.adminPassword",
                        appProperties.getAdminPassword(),
                        bindingResult);

    if (HSMTypeIdentifier.isUsingHSM(appProperties.getHsmType()))
    {

      checkFieldIsInt("applicationProperties.hsmKeysDelete",
                      appProperties.getHsmKeysDelete(),
                      bindingResult);

      checkNonBlankString("applicationProperties.pkcs11ConfigProviderPath",
                          appProperties.getPkcs11ConfigProviderPath(),
                          bindingResult);

      checkNonBlankString("applicationProperties.pkcs11HsmPassword",
                          appProperties.getPkcs11HsmPassword(),
                          bindingResult);
    }
  }
}

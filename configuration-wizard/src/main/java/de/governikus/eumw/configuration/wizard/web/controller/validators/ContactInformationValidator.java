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
 * created at: 15.02.2018 - 13:08 <br>
 * <br>
 */
public class ContactInformationValidator extends ViewValidator
{

  @Override
  public void validateView(ConfigurationForm configurationForm, BindingResult bindingResult)
  {
    checkMultipartFile("eidasmiddlewareProperties.serviceProviderMetadataFile",
                       configurationForm.getEidasmiddlewareProperties().getServiceProviderMetadataFile(),
                       bindingResult);
    checkForXmlContent("eidasmiddlewareProperties.serviceProviderMetadataFile",
                       configurationForm.getEidasmiddlewareProperties().getServiceProviderMetadataFileBytes(),
                       bindingResult);
    checkNamedObject("eidasmiddlewareProperties.metadataSignatureCertificate",
                     configurationForm.getEidasmiddlewareProperties().getMetadataSignatureCertificate(),
                     bindingResult, true);
    checkNamedObject("eidasmiddlewareProperties.middlewareSignKeystore",
                     configurationForm.getEidasmiddlewareProperties().getMiddlewareSignKeystore(),
                     bindingResult, false);
    checkNamedObject("eidasmiddlewareProperties.middlewareCryptKeystore",
                     configurationForm.getEidasmiddlewareProperties().getMiddlewareCryptKeystore(),
                     bindingResult, false);
    checkNonBlankString("eidasmiddlewareProperties.countryCode",
                        configurationForm.getEidasmiddlewareProperties().getCountryCode(),
                        bindingResult);
  }
}

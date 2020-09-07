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

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;

import org.springframework.validation.BindingResult;

import de.governikus.eumw.configuration.wizard.identifier.HSMTypeIdentifier;
import de.governikus.eumw.configuration.wizard.web.model.ConfigurationForm;
import de.governikus.eumw.utils.xml.XmlHelper;


/**
 * project: eumw <br>
 * author Pascal Knueppel <br>
 * created at: 15.02.2018 - 13:08 <br>
 * <br>
 */
public class EidasPropertiesValidator extends ViewValidator
{

  private static final String WIZARD_STATUS_VALIDATION_INCORRECT_METADATA = "wizard.status.validation.incorrect.metadata";

  private static final String INVALID_XML = "Invalid xml.";

  @Override
  public void validateView(ConfigurationForm configurationForm, BindingResult bindingResult)
  {
    if (configurationForm.getEidasmiddlewareProperties().getServiceProviderMetadataFiles().size() == 0)
    {
      bindingResult.reject("wizard.status.validation.missing.metadata",
                           "You must upload at least one metadata file.");
    }
    configurationForm.getEidasmiddlewareProperties()
                     .getServiceProviderMetadataFiles()
                     .forEach((String fileName, byte[] content) -> {
                       if (content == null || content.length == 0)
                       {
                         bindingResult.reject(WIZARD_STATUS_VALIDATION_INCORRECT_METADATA,
                                              new Object[]{fileName},
                                              INVALID_XML);
                         return;
                       }
                       try
                       {
                         if (!XmlHelper.isXmlWellFormed(new String(content, StandardCharsets.UTF_8.name())))
                         {
                           bindingResult.reject(WIZARD_STATUS_VALIDATION_INCORRECT_METADATA,
                                                new Object[]{fileName},
                                                INVALID_XML);
                         }
                       }
                       catch (UnsupportedEncodingException ex)
                       {
                         bindingResult.reject(WIZARD_STATUS_VALIDATION_INCORRECT_METADATA,
                                              new Object[]{fileName},
                                              INVALID_XML);
                       }
                     });
    checkNamedObject("eidasmiddlewareProperties.metadataSignatureCertificate",
                     configurationForm.getEidasmiddlewareProperties().getMetadataSignatureCertificate(),
                     bindingResult,
                     true);

    if (!HSMTypeIdentifier.isUsingHSM(configurationForm.getApplicationProperties().getHsmType()))
    {
      checkNamedObject("eidasmiddlewareProperties.middlewareSignKeystore",
                       configurationForm.getEidasmiddlewareProperties().getMiddlewareSignKeystore(),
                       bindingResult,
                       false);
    }

    checkNamedObject("eidasmiddlewareProperties.middlewareCryptKeystore",
                     configurationForm.getEidasmiddlewareProperties().getMiddlewareCryptKeystore(),
                     bindingResult,
                     false);

    checkNonBlankString("eidasmiddlewareProperties.countryCode",
                        configurationForm.getEidasmiddlewareProperties().getCountryCode(),
                        bindingResult);
  }
}

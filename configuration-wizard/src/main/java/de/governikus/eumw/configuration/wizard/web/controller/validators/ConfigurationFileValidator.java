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
import org.springframework.web.multipart.MultipartFile;

import de.governikus.eumw.configuration.wizard.web.model.ConfigurationForm;
import de.governikus.eumw.poseidas.config.schema.PoseidasCoreConfiguration;
import de.governikus.eumw.utils.xml.XmlHelper;


/**
 * project: eumw <br>
 * author Pascal Knueppel <br>
 * created at: 27.03.2018 - 07:56 <br>
 * <br>
 * this validator is used for configuration files that will be uploaded. It will succeed if no or only valid
 * files have been uploaded.
 */
public class ConfigurationFileValidator extends ViewValidator
{

  /**
   * @param configurationForm the configuration form to be validated
   * @param bindingResult the spring validation context object to add the errors directly
   */
  @Override
  public void validateView(ConfigurationForm configurationForm, BindingResult bindingResult)
  {
    MultipartFile poseidasFile = configurationForm.getPoseidasConfig().getPoseidasConfigXmlFile();

    // we use this variable to determine if additional errors were found. If yes we will not override the
    // holder variable that holds the uploaded configuration from before
    checkXmlFile("poseidasConfig.poseidasConfigXmlFile", poseidasFile, bindingResult).ifPresent(xml -> {
      PoseidasCoreConfiguration coreConfiguration = XmlHelper.unmarshal(xml, PoseidasCoreConfiguration.class);
      configurationForm.getPoseidasConfig().setCoreConfig(coreConfiguration);
    });
  }
}

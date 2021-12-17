/*
 * Copyright (c) 2021 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.configuration.wizard.web.model;

import java.util.Arrays;
import java.util.List;

import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ModelAttribute;

import de.governikus.eumw.configuration.wizard.identifier.HSMTypeIdentifier;
import de.governikus.eumw.configuration.wizard.web.utils.WizardPage;


@ControllerAdvice
public class GlobalModelAttribute
{

  @ModelAttribute("BASE_PATH_VIEW")
  public WizardPage basePathView()
  {
    return WizardPage.BASE_PATH_VIEW;
  }

  @ModelAttribute("UPLOAD_CONFIG_PROPERTIES_VIEW")
  public WizardPage uploadConfigPropertiesView()
  {
    return WizardPage.UPLOAD_CONFIG_PROPERTIES_VIEW;
  }

  @ModelAttribute("APPLICATION_PROPERTIES_VIEW")
  public WizardPage applicationPropertiesView()
  {
    return WizardPage.APPLICATION_PROPERTIES_VIEW;
  }

  @ModelAttribute("POSEIDAS_CORE_VIEW")
  public WizardPage poseidasCoreView()
  {
    return WizardPage.POSEIDAS_CORE_VIEW;
  }

  @ModelAttribute("EIDAS_PROPERTIES_VIEW")
  public WizardPage eidasPropertiesView()
  {
    return WizardPage.EIDAS_PROPERTIES_VIEW;
  }

  @ModelAttribute("SAVE_LOCATION_VIEW")
  public WizardPage saveLocationView()
  {
    return WizardPage.SAVE_LOCATION_VIEW;
  }

  @ModelAttribute("NUMBER_OF_PAGES")
  public int numberOfPages()
  {
    return WizardPage.values().length;
  }

  @ModelAttribute("HSM_TYPE_IDENTIFIER")
  public List<HSMTypeIdentifier> hsmTypeIdentifier()
  {
    return Arrays.asList(HSMTypeIdentifier.values());
  }
}

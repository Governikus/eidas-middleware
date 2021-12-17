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

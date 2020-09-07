/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.configuration.wizard.web.utils;

import java.util.Arrays;

import de.governikus.eumw.configuration.wizard.web.controller.validators.ApplicationPropertiesValidator;
import de.governikus.eumw.configuration.wizard.web.controller.validators.BasePathValidator;
import de.governikus.eumw.configuration.wizard.web.controller.validators.ConfigurationFileValidator;
import de.governikus.eumw.configuration.wizard.web.controller.validators.EidasPropertiesValidator;
import de.governikus.eumw.configuration.wizard.web.controller.validators.PoseidasCoreConfigValidator;
import de.governikus.eumw.configuration.wizard.web.controller.validators.SaveLocationValidator;
import de.governikus.eumw.configuration.wizard.web.controller.validators.ViewValidator;
import lombok.AccessLevel;
import lombok.Getter;


/**
 * project: eumw <br>
 * author Pascal Knueppel <br>
 * created at: 19.02.2018 - 08:07 <br>
 * <br>
 * This class holds all wizard pages.
 */
public enum WizardPage
{

  /**
   * a keyword for loading the page material with the application.properties settings
   */
  BASE_PATH_VIEW(Identifier.BASE_PATH_CONFIG, new BasePathValidator(), null, Identifier.UPLOAD_CONFIG),

  /**
   * a keyword for loading the page material with the application.properties settings
   */
  UPLOAD_CONFIG_PROPERTIES_VIEW(Identifier.UPLOAD_CONFIG,
                                new ConfigurationFileValidator(),
                                Identifier.BASE_PATH_CONFIG,
                                Identifier.APP_PROPERTIES),

  /**
   * a keyword for loading the page material with the application.properties settings
   */
  APPLICATION_PROPERTIES_VIEW(Identifier.APP_PROPERTIES,
                              new ApplicationPropertiesValidator(),
                              Identifier.UPLOAD_CONFIG,
                              Identifier.POSEIDAS_CORE),

  /**
   * leads to the page where the POSeIDAS core settings can be set
   */
  POSEIDAS_CORE_VIEW(Identifier.POSEIDAS_CORE,
                     new PoseidasCoreConfigValidator(),
                     Identifier.APP_PROPERTIES,
                     Identifier.EIDAS_PROPERTIES),

  /**
   * this view is to enter the eidasmiddleware.properties configuration
   */
  EIDAS_PROPERTIES_VIEW(Identifier.EIDAS_PROPERTIES,
                        new EidasPropertiesValidator(),
                        Identifier.POSEIDAS_CORE,
                        Identifier.SAVE_LOCATION),

  /**
   * in this view the user can set the save location for the configuration
   */
  SAVE_LOCATION_VIEW(Identifier.SAVE_LOCATION,
                     new SaveLocationValidator(),
                     Identifier.EIDAS_PROPERTIES,
                     null)

  ;

  /**
   * each page is bound to a specific view validator
   */
  @Getter
  private ViewValidator viewValidator;

  /**
   * represents the identifier for this view
   */
  @Getter(AccessLevel.PRIVATE)
  private Identifier thisIdentifier;

  /**
   * the previous page that was before this instance
   */
  private Identifier previousPage;

  /**
   * the next page that will follow on the given page
   */
  private Identifier nextPage;

  WizardPage(Identifier thisIdentifier,
             ViewValidator viewValidator,
             Identifier previousPage,
             Identifier nextPage)
  {
    this.viewValidator = viewValidator;
    this.thisIdentifier = thisIdentifier;
    this.nextPage = nextPage;
    this.previousPage = previousPage;
  }

  /**
   * will return the next page
   */
  public WizardPage getNextPage()
  {
    return Arrays.stream(values())
                 .filter(wizardPage -> wizardPage.getThisIdentifier().equals(nextPage))
                 .findAny()
                 .orElse(null);
  }

  /**
   * will return the previous page
   */
  public WizardPage getPreviousPage()
  {
    return Arrays.stream(values())
                 .filter(wizardPage -> wizardPage.getThisIdentifier().equals(previousPage))
                 .findAny()
                 .orElse(null);
  }

  /**
   * this method tells us which pagenumber this page represents
   *
   * @return the page number of the current page
   */
  public int getPageNumber()
  {
    int page = 1;
    for ( WizardPage wizardPage : values() )
    {
      if (this.equals(wizardPage))
      {
        break;
      }
      page++;
    }
    return page;
  }

  /**
   * this inner class is used for static identifier references for the single pages. This is used as
   * workaround in order for the views declarations to reference one to another
   */
  private enum Identifier
  {
    /**
     * identifier for the page where the base-path for the configuration can be set
     */
    BASE_PATH_CONFIG,
    /**
     * identifier for the page where already existing configurations can be uploaded
     */
    UPLOAD_CONFIG,
    APP_PROPERTIES,
    POSEIDAS_CORE,
    EIDAS_PROPERTIES,
    /**
     * identifier for the page where the save-location can be set
     */
    SAVE_LOCATION
  }
}

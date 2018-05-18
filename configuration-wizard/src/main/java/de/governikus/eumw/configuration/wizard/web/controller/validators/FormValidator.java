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
import de.governikus.eumw.configuration.wizard.web.utils.WizardPage;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;


/**
 * project: eumw <br>
 * author Pascal Knueppel <br>
 * created at: 15.02.2018 - 08:03 <br>
 * <br>
 * we are using a configuration wizard that is constantly giving the whole configuration in any request to the
 * server. For us to properly validate the form in its single steps we must validate each step by manual
 * checks instead of using bean validations. This is because the bean validations would fail for the
 * configurations that have not been set yet for they will only be available on the coming pages.
 */
@Slf4j
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class FormValidator
{

  /**
   * this method will do the validation of the form for the current page
   *
   * @param currentPage the current page that also holds is own validator
   * @param configurationForm the form that contains the data that should be validated
   * @param bindingResult the spring validation context object to add the errors directly
   */
  public static void validateView(WizardPage currentPage,
                                  ConfigurationForm configurationForm,
                                  BindingResult bindingResult)
  {
    if (currentPage.getViewValidator() != null)
    {
      currentPage.getViewValidator().validateView(configurationForm, bindingResult);
    }
  }

}

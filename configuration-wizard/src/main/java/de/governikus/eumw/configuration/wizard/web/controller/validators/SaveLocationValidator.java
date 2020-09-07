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

import java.io.File;

import org.apache.commons.lang3.StringUtils;
import org.springframework.validation.BindingResult;

import de.governikus.eumw.configuration.wizard.web.model.ConfigurationForm;


/**
 * author Pascal Knueppel <br>
 * created at: 06.04.2018 - 14:30 <br>
 * <br>
 * this validator is used to validate the given path at the save location from the view
 */
public class SaveLocationValidator extends ViewValidator
{

  /**
   * {@inheritDoc}
   */
  @Override
  public void validateView(ConfigurationForm configurationForm, BindingResult bindingResult)
  {
    final String saveLocationId = "saveLocation";
    if (StringUtils.isBlank(configurationForm.getSaveLocation()))
    {
      bindingResult.rejectValue(saveLocationId, null, "save location must not be blank");
      return;
    }
    File file = new File(StringUtils.stripToEmpty(configurationForm.getSaveLocation()));
    if (!file.exists())
    {
      if (!file.mkdirs())
      {
        bindingResult.rejectValue(saveLocationId,
                                  null,
                                  "could not create directory at path '" + file.getAbsolutePath() + "'");
        return;
      }
    }
    else if (!file.isDirectory())
    {
      bindingResult.rejectValue(saveLocationId,
                                null,
                                "path is not a directory '" + file.getAbsolutePath() + "'");
      return;
    }

    if (!file.canWrite())
    {
      bindingResult.rejectValue(saveLocationId,
                                null,
                                "path under '" + file.getAbsolutePath() + "' is not writable");
    }
  }
}

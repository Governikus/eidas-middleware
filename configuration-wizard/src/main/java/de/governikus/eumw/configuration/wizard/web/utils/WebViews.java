/*
 * Copyright (c) 2019 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.configuration.wizard.web.utils;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

/**
 * project: eumw <br>
 * author Pascal Knueppel <br>
 * created at: 12.02.2018 - 10:50 <br>
 * <br>
 * this class contains the view names of the html pages as constants
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class WebViews
{

  /**
   * the configuration wizard html view name
   */
  public static final String CONFIG_WIZARD = "config-wizard.html";

  /**
   * the view after a successful save
   */
  public static final String SAVE_SUCCESS = "save-result.html";
}

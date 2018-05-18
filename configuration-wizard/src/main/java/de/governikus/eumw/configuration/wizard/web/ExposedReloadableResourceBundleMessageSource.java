/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.configuration.wizard.web;

import java.util.Locale;
import java.util.Properties;

import org.springframework.context.support.ReloadableResourceBundleMessageSource;


/**
 * This class provides merged resource messages as java.util.Properties.
 */
public class ExposedReloadableResourceBundleMessageSource extends ReloadableResourceBundleMessageSource
{

  /**
   * Gets all messages for presented Locale.
   *
   * @param locale
   * @return all messages
   */
  public Properties getMessages(Locale locale)
  {
    return getMergedProperties(locale).getProperties();
  }
}

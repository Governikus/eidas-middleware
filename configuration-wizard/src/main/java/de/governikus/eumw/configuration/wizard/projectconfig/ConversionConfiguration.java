/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.configuration.wizard.projectconfig;

import org.springframework.context.annotation.Configuration;
import org.springframework.format.FormatterRegistry;

import de.governikus.eumw.configuration.wizard.web.converter.CertificateConverter;
import de.governikus.eumw.configuration.wizard.web.converter.KeystoreConverter;


/**
 * project: eumw <br>
 * author: Pascal Knueppel <br>
 * created at: 24.12.2017 - 14:17 <br>
 * <br>
 * this configuration will add all converters that will simplify the communication with the html-view to the
 * spring context
 */
@Configuration
public class ConversionConfiguration extends WebAppConfig
{

  /**
   * adds all converters that will simplify the communication with the html-views
   */
  @Override
  public void addFormatters(FormatterRegistry registry)
  {
    registry.addConverter(new CertificateConverter());
    registry.addConverter(new KeystoreConverter());
  }
}

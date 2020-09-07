/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.configuration.wizard.web.converter;

import org.springframework.core.convert.converter.Converter;

import de.governikus.eumw.configuration.wizard.web.handler.HandlerHolder;
import de.governikus.eumw.configuration.wizard.web.handler.KeystoreHandler;
import de.governikus.eumw.configuration.wizard.web.model.KeystoreForm;


/**
 * project: eumw <br>
 * author: Pascal Knueppel <br>
 * created at: 24.12.2017 - 13:57 <br>
 * <br>
 * this converter will convert keystore names that are sent from a html view into a keystore instance by
 * reading it from the {@link KeystoreHandler}
 */
public class KeystoreConverter implements Converter<String, KeystoreForm>
{

  /**
   * will convert a name value from the view to a {@link KeystoreForm} instance
   *
   * @param source the name of the keystore
   * @return the keystore or null if the name is not found
   */
  @Override
  public KeystoreForm convert(String source)
  {
    return HandlerHolder.getKeystoreHandler().getByName(source);
  }
}

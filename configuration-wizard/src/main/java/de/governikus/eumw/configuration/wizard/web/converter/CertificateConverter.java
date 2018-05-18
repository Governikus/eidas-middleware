/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.configuration.wizard.web.converter;

import org.springframework.core.convert.converter.Converter;

import de.governikus.eumw.configuration.wizard.web.handler.CertificateHandler;
import de.governikus.eumw.configuration.wizard.web.handler.HandlerHolder;
import de.governikus.eumw.configuration.wizard.web.model.CertificateForm;


/**
 * project: eumw <br>
 * author: Pascal Knueppel <br>
 * created at: 24.12.2017 - 13:57 <br>
 * <br>
 * this converter will convert certificate names that are sent from a html view into a certificate instance by
 * reading it from the {@link CertificateHandler}
 */
public class CertificateConverter implements Converter<String, CertificateForm>
{

  /**
   * will convert a name value from the view to a {@link CertificateForm} instance
   * 
   * @param source the name of the certificate
   * @return the certificate or null if the name is not found
   */
  @Override
  public CertificateForm convert(String source)
  {
    return HandlerHolder.getCertificateHandler().getByName(source);
  }
}

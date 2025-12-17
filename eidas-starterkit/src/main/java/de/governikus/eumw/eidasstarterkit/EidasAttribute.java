/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.eidasstarterkit;

import org.opensaml.saml.saml2.core.Attribute;

import de.governikus.eumw.eidasstarterkit.person_attributes.EidasPersonAttributes;


/**
 * @author hohnholt
 */
public interface EidasAttribute
{

  /**
   * @return An SAML XML attribute as String
   */
  public Attribute generate();

  /**
   * @return the type
   */
  public EidasPersonAttributes type();

  /**
   * Set the attribute value
   */
  public void setValue(String value);

  /**
   * Get a string-representation of the attribute value
   *
   * @return a String containing the attribute value
   */
  public String getValue();
}

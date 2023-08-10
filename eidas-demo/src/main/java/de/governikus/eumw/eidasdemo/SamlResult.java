/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.eidasdemo;

import java.util.List;

import de.governikus.eumw.eidasstarterkit.EidasAttribute;
import lombok.Data;


/**
 * Simple class to hold some data retrieved from the SAML response
 */
@Data
class SamlResult
{

  /**
   * The SAML response as a string
   */
  private String samlResponse;

  /**
   * The value from the relayState parameter
   */
  private String relayState;

  /**
   * The extracted attributes from the SAML response
   */
  private List<EidasAttribute> attributes;

  /**
   * This may contain an error message in case there was an exception during the processing of the SAML response
   */
  private String errorDetails;

  /**
   * The level of assurance from the assertion
   */
  private String levelOfAssurance;

  private String assertion;

}

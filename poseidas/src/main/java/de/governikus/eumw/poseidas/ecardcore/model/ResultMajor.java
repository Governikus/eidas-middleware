/*
 * Copyright (c) 2019 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.ecardcore.model;

/**
 * ResultMajor Specify the type of the result, of an ecard-API operation: Error, Warning, Ok
 * <p>
 * Look for further information in OASIS DSS oasis-dss-core-spec-v1.0-os.pdf
 * </p>
 * Auto generated Java file - please do not edit (Bitte nicht editieren) Was build on Fri Feb 06 12:02:27 CET
 * 2015 by stahlbock
 *
 * @author XSD2Java
 */
public enum ResultMajor
{

  /**
   * URI value: http://www.bsi.bund.de/ecard/api/1.1/resultmajor#ok
   */
  OK("http://www.bsi.bund.de/ecard/api/1.1/resultmajor#ok"),
  /**
   * URI value: http://www.bsi.bund.de/ecard/api/1.1/resultmajor#error
   */
  ERROR("http://www.bsi.bund.de/ecard/api/1.1/resultmajor#error"),
  /**
   * URI value: http://www.bsi.bund.de/ecard/api/1.1/resultmajor#warning
   */
  WARNING("http://www.bsi.bund.de/ecard/api/1.1/resultmajor#warning");

  private final String uri;

  ResultMajor(String uri)
  {
    this.uri = uri;
  }

  @Override
  public String toString()
  {
    return uri;
  }

}

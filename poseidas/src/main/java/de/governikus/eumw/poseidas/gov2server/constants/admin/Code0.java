/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.gov2server.constants.admin;

/**
 * Management code class for codes requiring no parameters.
 */
public class Code0 extends ManagementCode
{

  private static final long serialVersionUID = 5095551331546131042L;

  /**
   * Creates a new Code0 object.
   *
   * @param code unique identifier of the message code
   */
  Code0(String code)
  {
    super(code);
  }

  /**
   * Create a new ManagementErrorMessage with this error code and given details
   */
  public ManagementMessage createMessage()
  {
    return new ManagementMessage(this, null);
  }
}

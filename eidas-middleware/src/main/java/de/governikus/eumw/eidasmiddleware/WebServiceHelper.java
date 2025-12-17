/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.eidasmiddleware;

import oasis.names.tc.dss._1_0.core.schema.Result;


/**
 * Helper class for web service functionality
 */
public final class WebServiceHelper
{

  private WebServiceHelper()
  {

  }

  /**
   * Return true if the result codes match the expected values
   *
   * @param result
   * @param expectedResultMajor
   * @param expectedResultMinor
   */
  public static boolean checkResult(Result result, String expectedResultMajor, String expectedResultMinor)
  {
    return expectedResultMajor != null && expectedResultMajor.equals(result.getResultMajor())
           && ((expectedResultMinor == null && result.getResultMinor() == null)
               || result.getResultMinor().equals(expectedResultMinor));
  }
}

/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.eidasstarterkit;

import org.apache.commons.lang3.StringEscapeUtils;
import org.apache.commons.lang3.StringUtils;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import se.swedenconnect.opensaml.eidas.ext.SPTypeEnumeration;


/**
 * Helper class to get the SPType Enum from a String
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class SPTypeHelper
{

  /**
   * Get the matching {@link SPTypeEnumeration} instance for the given spTypeString. The matching is done case
   * insensitive. If the spTypeString does not equal private or public, a {@link IllegalArgumentException} is
   * thrown.
   */
  public static SPTypeEnumeration getSPTypeFromString(String spTypeString)
  {
    if (StringUtils.equalsIgnoreCase(SPTypeEnumeration.PRIVATE.getValue(), spTypeString))
    {
      return SPTypeEnumeration.PRIVATE;
    }
    else if (StringUtils.equalsIgnoreCase(SPTypeEnumeration.PUBLIC.getValue(), spTypeString))
    {
      return SPTypeEnumeration.PUBLIC;
    }
    else
    {
      throw new IllegalArgumentException("Received Invalid SPType: "
                                         + StringEscapeUtils.escapeHtml4(spTypeString));
    }
  }
}

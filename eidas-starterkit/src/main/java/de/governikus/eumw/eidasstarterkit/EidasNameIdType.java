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

import org.opensaml.saml.saml2.core.NameIDType;

import de.governikus.eumw.eidascommon.ErrorCode;
import de.governikus.eumw.eidascommon.ErrorCodeException;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;


@Getter
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public enum EidasNameIdType
{
  PERSISTENT(NameIDType.PERSISTENT), TRANSIENT(NameIDType.TRANSIENT), UNSPECIFIED(NameIDType.UNSPECIFIED);

  private final String value;

  static EidasNameIdType getValueOf(String s) throws ErrorCodeException
  {
    for ( EidasNameIdType e : EidasNameIdType.values() )
    {
      if (e.value.equals(s))
      {
        return e;
      }
    }
    throw new ErrorCodeException(ErrorCode.ILLEGAL_REQUEST_SYNTAX, "Unsupported NameIdType value: " + s);
  }
}

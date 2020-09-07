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

import de.governikus.eumw.eidascommon.ErrorCode;
import de.governikus.eumw.eidascommon.ErrorCodeException;


/**
 * @author hohnholt
 */
public enum EidasLoA
{

  /**
   * http://eidas.europa.eu/LoA/low
   */
  LOW("http://eidas.europa.eu/LoA/low"),

  /**
   * http://eidas.europa.eu/LoA/substantial
   */
  SUBSTANTIAL("http://eidas.europa.eu/LoA/substantial"),

  /**
   * http://eidas.europa.eu/LoA/high
   */
  HIGH("http://eidas.europa.eu/LoA/high");

  public final String value;

  private EidasLoA(String value)
  {
    this.value = value;
  }

  static EidasLoA getValueOf(String s) throws ErrorCodeException
  {
    for ( EidasLoA e : EidasLoA.values() )
    {
      if (e.value.equals(s))
      {
        return e;
      }
    }
    throw new ErrorCodeException(ErrorCode.ILLEGAL_REQUEST_SYNTAX, "Unsupported EidasLoA value:" + s);
  }
}

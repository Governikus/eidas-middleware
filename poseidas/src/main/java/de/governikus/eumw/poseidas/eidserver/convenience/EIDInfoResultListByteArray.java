/*
 * Copyright (c) 2019 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.eidserver.convenience;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;


public class EIDInfoResultListByteArray implements EIDInfoResult, Serializable
{

  private static final long serialVersionUID = 2L;

  private final List<byte[]> result;

  EIDInfoResultListByteArray(List<byte[]> result)
  {
    super();
    this.result = new ArrayList<>(result);
  }

  public List<byte[]> getResult()
  {
    return Collections.unmodifiableList(this.result);
  }

  @Override
  public int hashCode()
  {
    return (result.isEmpty()) ? 0 : result.hashCode();
  }

  @Override
  public boolean equals(Object obj)
  {
    if (this == obj)
    {
      return true;
    }
    if (obj == null || getClass() != obj.getClass())
    {
      return false;
    }

    EIDInfoResultListByteArray other = (EIDInfoResultListByteArray)obj;
    if (this.result.isEmpty() && other.result.isEmpty())
    {
      return true;
    }

    if (this.result.size() != other.result.size())
    {
      return false;
    }

    for ( int i = 0 ; i < this.result.size() ; i++ )
    {
      if (!Arrays.equals(this.result.get(i), (other.result.get(i))))
      {
        return false;
      }
    }
    return true;
  }
}

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
import java.math.BigInteger;
import java.util.Arrays;


/**
 * This is a restricted ID result. This should only be returned in response to a restricted identification.
 *
 * @author Hauke Mehrtens
 */
public class EIDInfoResultRestrictedID implements EIDInfoResult, Serializable
{

  private static final long serialVersionUID = 2L;

  private final byte[] id1;

  private final byte[] id2;

  EIDInfoResultRestrictedID(byte[] id1, byte[] id2)
  {
    this.id1 = id1;
    this.id2 = id2;
  }

  public byte[] getID1()
  {
    return id1;
  }

  public byte[] getID2()
  {
    return id2;
  }

  @Override
  public int hashCode()
  {
    final int prime = 31;
    int result = prime + Arrays.hashCode(id1);
    result = prime * result + Arrays.hashCode(id2);
    return result;
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
    EIDInfoResultRestrictedID other = (EIDInfoResultRestrictedID)obj;
    if (!Arrays.equals(id1, other.id1))
    {
      return false;
    }
    if (!Arrays.equals(id2, other.id2))
    {
      return false;
    }
    return true;
  }

  @Override
  public String toString()
  {
    StringBuilder builder = new StringBuilder();
    builder.append("id1: ");
    if (id1 != null)
    {
      builder.append(new BigInteger(id1).abs().toString(16));
    }
    else
    {
      builder.append("null");
    }
    builder.append(" id2: ");
    if (id2 != null)
    {
      builder.append(new BigInteger(id2).abs().toString(16));
    }
    else
    {
      builder.append("null");
    }
    return builder.toString();
  }
}

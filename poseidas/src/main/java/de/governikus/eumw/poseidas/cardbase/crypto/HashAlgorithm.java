/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardbase.crypto;


import org.bouncycastle.asn1.x509.DigestInfo;

import de.governikus.eumw.poseidas.cardbase.AssertUtil;
import de.governikus.eumw.poseidas.cardbase.ByteUtil;
import de.governikus.eumw.poseidas.cardbase.asn1.OID;
import lombok.Getter;


/**
 * Hash algorithm.
 *
 * @see HashConstants
 * @see DigestInfo
 * @see HashAlgorithmEnum
 * @author Jens Wothe, jw@bos-bremen.de
 */
@Getter
public class HashAlgorithm extends OID implements HashInfo
{

  // name of algorithm
  private final String name;

  // length of hash
  private final int hashLength;

  /**
   * Constructor.
   *
   * @param name name of algorithm, <code>null</code> or empty String not permitted
   * @param hashLength length of related hash, value greater equals than 1 only permitted
   * @param oidString OID as String, <code>null</code> or empty String not permitted
   * @throws IllegalArgumentException if arguments invalid
   */
  HashAlgorithm(String name, int hashLength, String oidString)
  {
    super(oidString);
    AssertUtil.notNullOrEmpty(name, "name of algorithm");
    AssertUtil.positive(hashLength, "length of  hash");
    this.name = name;
    this.hashLength = hashLength;
  }

  /** {@inheritDoc} */
  @Override
  public int hashCode()
  {
    final int prime = 31;
    int result = super.hashCode();
    result = prime * result + hashLength;
    result = prime * result + ((name == null) ? 0 : name.hashCode());
    return result;
  }

  /** {@inheritDoc} */
  @Override
  public boolean equals(Object obj)
  {
    if (this == obj)
    {
      return true;
    }
    if (!super.equals(obj))
    {
      return false;
    }
    if (getClass() != obj.getClass())
    {
      return false;
    }
    HashAlgorithm other = (HashAlgorithm)obj;
    if (hashLength != other.hashLength)
    {
      return false;
    }
    if (name == null)
    {
      if (other.name != null)
      {
        return false;
      }
    }
    else if (!name.equals(other.name))
    {
      return false;
    }
    return true;
  }

  /** {@inheritDoc} */
  @Override
  public byte[] getOIDValue()
  {
    return ByteUtil.copy(super.getValue());
  }

  /** {@inheritDoc} */
  @Override
  public OID getOID()
  {
    return this;
  }
}

/*
 * Copyright (c) 2019 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.pki;

import java.io.Serializable;
import java.util.Objects;

import javax.persistence.Embeddable;


/**
 * Composite primary key for certificate chain elements
 *
 * @author tt
 */
@Embeddable
public class CertInChainPK implements Serializable
{

  private static final long serialVersionUID = -6815901659279702286L;

  private String refID;

  private int posInChain;

  /**
   * create new instance
   *
   * @param refID
   * @param posInChain
   */
  CertInChainPK(String refID, int posInChain)
  {
    super();
    this.refID = refID;
    this.posInChain = posInChain;
  }


  /**
   * probably needed by server
   */
  public CertInChainPK()
  {
    // nothing to do here
  }

  /**
   * Return the artificial primary key of the corresponding TerminalPermission entity
   */
  public String getRefID()
  {
    return refID;
  }

  /**
   * Return the position in the chain beginning with 0 - root
   */
  public int getPosInChain()
  {
    return posInChain;
  }

  @Override
  public int hashCode()
  {
    return posInChain + Objects.hashCode(refID);
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
    CertInChainPK other = (CertInChainPK)obj;
    return posInChain == other.posInChain && Objects.equals(refID, other.refID);
  }

  @Override
  public String toString()
  {
    return refID + "." + posInChain;
  }
}

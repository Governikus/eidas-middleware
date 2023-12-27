/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
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

import jakarta.persistence.Embeddable;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;


/**
 * Composite primary key for certificate chain elements
 *
 * @author tt
 */
@Getter
@AllArgsConstructor(access = AccessLevel.PACKAGE)
@NoArgsConstructor(access = AccessLevel.PUBLIC)
@Embeddable
public class CertInChainPK implements Serializable
{

  private static final long serialVersionUID = -6815901659279702286L;

  /**
   * The artificial primary key of the corresponding TerminalPermission entity
   */
  private String refID;

  /**
   * The position in the chain beginning with 0 - root
   */
  private int posInChain;

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

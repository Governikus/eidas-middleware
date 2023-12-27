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


/**
 * Primary key for a blacklist entry. All data in a blacklist entry is in the primary key.
 *
 * @author mehrtens
 */
@Embeddable
public class BlackListEntryPK implements Serializable
{

  private static final long serialVersionUID = 7249930585278477663L;

  private String sectorID;

  private String specificID;

  /**
   * Constructor needed by hibernate
   */
  public BlackListEntryPK()
  {
    // nothing to do here
  }

  /**
   * Creates a new Blacklist entry primary key.
   *
   * @param sectorID the sector ID of the service provider this blacklist is for, as base64.
   * @param specificID the id of the revoked new identity card, as base64.
   */
  BlackListEntryPK(String sectorID, String specificID)
  {
    this.sectorID = sectorID;
    this.specificID = specificID;
  }

  /**
   * Returns the sector ID of this entry as base64.
   */
  public String getSectorID()
  {
    return sectorID;
  }

  /**
   * Sets a new sector ID.
   *
   * @param id new ID
   */
  public void setSectorID(String id)
  {
    this.sectorID = id;
  }

  /**
   * Returns the specific ID of the revoked new identity card as base64.
   */
  public String getSpecificID()
  {
    return specificID;
  }

  @Override
  public int hashCode()
  {
    return Objects.hashCode(sectorID) * 2 + Objects.hashCode(specificID);
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
    BlackListEntryPK other = (BlackListEntryPK)obj;
    return Objects.equals(sectorID, other.sectorID) && Objects.equals(specificID, other.specificID);
  }
}

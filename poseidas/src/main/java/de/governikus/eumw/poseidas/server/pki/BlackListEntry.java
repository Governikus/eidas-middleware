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

import javax.persistence.EmbeddedId;
import javax.persistence.Entity;
import javax.persistence.NamedQuery;


/**
 * Persists Blacklist containing all revoked specificID for a specific service provider.
 *
 * @author hme
 */
@Entity
@NamedQuery(name = BlackListEntry.COUNT_SPECIFICID, query = "SELECT COUNT( b.key.specificID ) FROM BlackListEntry b WHERE b.key.sectorID = :"
                                                            + BlackListEntry.PARAM_SECTORID
                                                            + " AND b.key.specificID = :"
                                                            + BlackListEntry.PARAM_SPECIFICID)
@NamedQuery(name = BlackListEntry.SELECT_SPECIFICID_WHERE_SECTORID, query = "SELECT b.key.specificID FROM BlackListEntry b WHERE b.key.sectorID = :"
                                                                            + BlackListEntry.PARAM_SECTORID)
@NamedQuery(name = BlackListEntry.COUNT_SPECIFICID_WHERE_SECTORID, query = "SELECT COUNT( b.key.specificID ) FROM BlackListEntry b WHERE b.key.sectorID = :"
                                                                           + BlackListEntry.PARAM_SECTORID)
@NamedQuery(name = BlackListEntry.DELETE_WHERE_SECTORID, query = "DELETE FROM BlackListEntry WHERE key.sectorID = :"
                                                                 + BlackListEntry.PARAM_SECTORID)
@NamedQuery(name = BlackListEntry.DELETE_WHERE_SECTORID_AND_SPECIFICID, query = "DELETE FROM BlackListEntry WHERE key.sectorID = :"
                                                                                + BlackListEntry.PARAM_SECTORID
                                                                                + " AND key.specificID in :"
                                                                                + BlackListEntry.PARAM_SPECIFICID)
@NamedQuery(name = BlackListEntry.UPDATE_WHERE_SECTORID, query = "UPDATE BlackListEntry SET key.sectorID = :"
                                                                 + BlackListEntry.PARAM_NEWSECTORID
                                                                 + " WHERE key.sectorID = :"
                                                                 + BlackListEntry.PARAM_SECTORID)
public class BlackListEntry implements Serializable
{

  private static final long serialVersionUID = -7951678084421950262L;

  static final String COUNT_SPECIFICID = "countSpecificidWhereSectoridAndSpecificid";

  static final String SELECT_SPECIFICID_WHERE_SECTORID = "selectSpecificidWhereSectorid";

  static final String COUNT_SPECIFICID_WHERE_SECTORID = "countSpecificidWhereSectorid";

  static final String DELETE_WHERE_SECTORID = "deleteWhereSectorid";

  static final String DELETE_WHERE_SECTORID_AND_SPECIFICID = "deleteWhereSectoridAndSpecificid";

  static final String UPDATE_WHERE_SECTORID = "updateWhereSectorid";

  static final String PARAM_SECTORID = "pSectorID";

  static final String PARAM_NEWSECTORID = "pNewSectorID";

  static final String PARAM_SPECIFICID = "pSpecificID";

  @EmbeddedId
  private BlackListEntryPK key;

  /**
   * Constructor needed by hibernate
   */
  public BlackListEntry()
  {
    // nothing to do here
  }

  /**
   * Creates a new blacklist entry.
   *
   * @param key
   */
  BlackListEntry(BlackListEntryPK key)
  {
    this.key = key;
  }

  /**
   * Returns the primary key.
   */
  public BlackListEntryPK getKey()
  {
    return key;
  }
}

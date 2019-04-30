/*
 * Copyright (c) 2019 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.pki.caserviceaccess;

import de.governikus.eumw.poseidas.gov2server.GovManagementException;


/**
 * Wrapper for different versions of restrictedId service
 *
 * @author tautenhahn
 */
public abstract class RestrictedIdServiceWrapper
{

  public static final BlackListResult NO_NEW_DATA = new BlackListResult("no new data");

  /**
   * Return the blacklist deltas, or alternatively an URI to download the blacklist if available. Otherwise,
   * throw an exception.
   */
  public abstract BlackListResult getBlacklistResult(byte[] deltabase) throws GovManagementException;


  /**
   * return the sector public key for given sector ID.
   *
   * @throws GovManagementException
   */
  public abstract byte[] getSectorPublicKey(byte[] sectorId) throws GovManagementException;


  /**
   * Data object to hold the result of a blacklist request, either two delta lists or an URI to download the
   * complete list.
   */
  public static class BlackListResult
  {

    private String uri;

    private byte[] deltaAdded;

    private byte[] deltaRemoved;

    BlackListResult(String uri)
    {
      super();
      this.uri = uri;
    }

    BlackListResult(byte[] added, byte[] removed)
    {
      super();
      this.deltaAdded = added;
      this.deltaRemoved = removed;
    }

    public String getUri()
    {
      return this.uri;
    }

    public byte[] getDeltaAdded()
    {
      return this.deltaAdded;
    }

    public byte[] getDeltaRemoved()
    {
      return this.deltaRemoved;
    }
  }
}

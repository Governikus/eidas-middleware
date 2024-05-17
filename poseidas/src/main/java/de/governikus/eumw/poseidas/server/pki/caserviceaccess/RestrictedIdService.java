package de.governikus.eumw.poseidas.server.pki.caserviceaccess;

import de.governikus.eumw.poseidas.gov2server.GovManagementException;
import de.governikus.eumw.poseidas.server.pki.entities.TerminalPermission;
import lombok.Getter;


public interface RestrictedIdService
{

  /**
   * Requests a new block list.
   * @param deltabase The base from where the delta should be generated.
   * @param sectorID The identifier of this sector. E.g the {@link TerminalPermission#getSectorID()}.
   * @return
   *
   * @throws GovManagementException
   */
  BlackListResult getBlacklistResult(byte[] deltabase, byte[] sectorID) throws GovManagementException;

  byte[] getSectorPublicKey(byte[] sectorId) throws GovManagementException;

  /**
   * Data object to hold the result of a blacklist request, either two delta lists or an URI to download the complete
   * list.
   */
  @Getter
  class BlackListResult
  {

    private String uri;

    private byte[] deltaAdded;

    private byte[] deltaRemoved;

    public BlackListResult(String uri)
    {
      super();
      this.uri = uri;
    }

    public BlackListResult(byte[] added, byte[] removed)
    {
      super();
      this.deltaAdded = added;
      this.deltaRemoved = removed;
    }

  }
}

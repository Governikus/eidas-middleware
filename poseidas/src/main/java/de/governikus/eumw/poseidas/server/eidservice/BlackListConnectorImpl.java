/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.eidservice;

import java.io.IOException;

import de.governikus.eumw.poseidas.eidserver.ecardid.BlackListConnector;
import de.governikus.eumw.poseidas.server.pki.blocklist.BlockListService;


/**
 * Black list connector which gets data from poseidas database.
 *
 * @author tautenhahn
 */
public class BlackListConnectorImpl implements BlackListConnector
{

  private final byte[] sectorID;

  private final BlockListService blockListService;

  BlackListConnectorImpl(BlockListService blockListService, byte[] sectorID)
  {
    this.blockListService = blockListService;
    this.sectorID = sectorID;
  }

  @Override
  public boolean contains(byte[] sectorSpecificID) throws IOException
  {
    return blockListService.isOnBlockList(sectorID, sectorSpecificID);
  }

  @Override
  public byte[] getSectorID()
  {
    return sectorID;
  }

  /**
   * Re-initialize the transient field after de-serialization.
   */
  public Object readResolve() throws IOException
  {
    return this;
  }
}

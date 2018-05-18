/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.pki;

import de.governikus.eumw.poseidas.gov2server.GovManagementException;
import de.governikus.eumw.poseidas.gov2server.constants.admin.IDManagementCodes;
import de.governikus.eumw.poseidas.server.idprovider.config.EPAConnectorConfigurationDto;
import de.governikus.eumw.poseidas.server.idprovider.config.PkiConnectorConfigurationDto;


/**
 * Base class for the objects handling the BerCA requests.
 * 
 * @author tautenhahn
 */
class BerCaRequestHandlerBase
{

  /**
   * Persistence layer access
   */
  protected final TerminalPermissionAO facade;

  /**
   * ID of the persistence entry
   */
  protected final String entityId;

  /**
   * configuration of the BerCa connection
   */
  protected final PkiConnectorConfigurationDto pkiConfig;

  /**
   * configuration of the BerCa connection
   */
  protected final EPAConnectorConfigurationDto nPaConf;

  /**
   * Create new instance for current configuration
   * 
   * @param facade must be obtained by client
   */
  protected BerCaRequestHandlerBase(EPAConnectorConfigurationDto nPaConf, TerminalPermissionAO facade)
    throws GovManagementException
  {
    this.facade = facade;
    this.nPaConf = nPaConf;
    if (nPaConf == null)
    {
      throw new GovManagementException(
                                       IDManagementCodes.INVALID_INPUT_DATA.createMessage("this is not configurated for nPA"));
    }
    pkiConfig = nPaConf.getPkiConnectorConfiguration();
    this.entityId = nPaConf.getCVCRefID();
  }
}

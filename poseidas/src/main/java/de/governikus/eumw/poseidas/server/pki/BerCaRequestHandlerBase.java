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

import java.security.KeyStore;

import org.apache.commons.lang3.StringUtils;

import de.governikus.eumw.config.DvcaConfigurationType;
import de.governikus.eumw.config.ServiceProviderType;
import de.governikus.eumw.poseidas.gov2server.GovManagementException;
import de.governikus.eumw.poseidas.gov2server.constants.admin.IDManagementCodes;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationService;


/**
 * Base class for the objects handling the BerCA requests.
 *
 * @author tautenhahn
 */
class BerCaRequestHandlerBase
{

  /**
   * Optional HSM-based keystore containing TLS client key.
   */
  final KeyStore hsmKeyStore;

  /**
   * Persistence layer access
   */
  protected final TerminalPermissionAO facade;

  /**
   * ID of the persistence entry
   */
  protected final String cvcRefId;

  /**
   * configuration of the BerCa connection
   */
  protected final DvcaConfigurationType dvcaConfiguration;

  /**
   * configuration of the BerCa connection
   */
  protected final ServiceProviderType serviceProvider;

  protected final ConfigurationService configurationService;

  /**
   * Create new instance for current configuration
   *
   * @param facade must be obtained by client
   */
  protected BerCaRequestHandlerBase(ServiceProviderType serviceProvider,
                                    TerminalPermissionAO facade,
                                    KeyStore hsmKeyStore,
                                    ConfigurationService configurationService)
    throws GovManagementException
  {
    this.hsmKeyStore = hsmKeyStore;
    this.facade = facade;
    this.serviceProvider = serviceProvider;
    this.configurationService = configurationService;
    if (StringUtils.isBlank(serviceProvider.getDvcaConfigurationName()))
    {
      throw new GovManagementException(IDManagementCodes.INVALID_INPUT_DATA.createMessage("this is not configured for nPA"));
    }
    dvcaConfiguration = configurationService.getDvcaConfiguration(serviceProvider);
    this.cvcRefId = serviceProvider.getCVCRefID();
  }
}

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
 * Interface to wrap the different kinds of services behind which handle CVC requests.
 *
 * @author tautenhahn
 */
public interface TermAuthServiceWrapper
{

  /**
   * return the CA certificates of the CA
   *
   * @throws GovManagementException in case return code does not indicate success
   */
  byte[][] getCACertificates() throws GovManagementException;

  /**
   * send a CVC request
   *
   * @param request certificate request to send
   * @param messageId free unique String in case of asynchronous requests, null for synchronous requests
   * @param returnUrl URL of callback service in case of asynchronous requests, null for synchronous requests
   * @throws GovManagementException in case return code does not indicate success
   */
  byte[] requestCertificate(byte[] request, String messageId, String returnUrl) throws GovManagementException;
}

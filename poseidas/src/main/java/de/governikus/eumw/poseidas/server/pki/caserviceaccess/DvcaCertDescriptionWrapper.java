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


/**
 * Interface to service to fetch a certificate Description form a Ber CA. Only the D-Trust CA supports this
 * interface.
 *
 * @author mehrtens
 */
public interface DvcaCertDescriptionWrapper
{

  /**
   * Returns a certificate Description for a given hash.
   *
   * @param hash
   */
  byte[] getCertificateDescription(byte[] hash);
}

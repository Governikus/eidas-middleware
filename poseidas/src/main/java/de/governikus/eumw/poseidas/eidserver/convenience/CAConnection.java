/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.eidserver.convenience;

import java.util.List;


/**
 * Interface for connections to the CA certifying the public key from card. To be revamped once the details of
 * the connection are known.
 * 
 * @author Arne Stahlbock, arne.stahlbock@governikus.com
 */
public interface CAConnection
{

  /**
   * Submits the newly generated public key to the CA and receives the signed certificate.
   * 
   * @param key public key
   * @param dn distinguished name for certificate
   * @return list of certificates as byte-array, expected to contain 2 certificates, CA certificate at index 0
   *         and user certificate at index 1.
   */
  public abstract List<byte[]> submitPublicKey(byte[] key, String dn);

  /**
   * Reports successful writing of certificates to card.
   * 
   * @param success <code>true</code> for successfully written, <code>false</code> for error
   * @return <code>true</code> for accepted, <code>false</code> otherwise
   */
  public abstract boolean reportWrite(boolean success);
}

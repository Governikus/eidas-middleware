/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardserver.eac.ta;


import java.io.IOException;
import java.util.List;


/**
 * Interface for providing certificate chains and keys.
 * 
 * @author Arne Stahlbock, ast@bos-bremen.de
 */
public interface CertAndKeyProvider
{

  /**
   * Get certificate chain by holders of root and terminal certificates.
   * 
   * @param rootHolder holder of root certificate, <code>null</code> not permitted
   * @param termHolder holder of terminal certificate, <code>null</code> not permitted
   * @return List of certificates, <code>null</code> if not found, list expected to contain certificates in
   *         order from root at index 0 to child at highest index, list must not contain the root certificate
   *         itself and must not contain the terminal certificate
   * @throws IllegalArgumentException if any parameter <code>null</code>
   */
  public abstract List<byte[]> getCertChain(String rootHolder, String termHolder)
    throws IOException;

  /**
   * Get key by its holder.
   * 
   * @param holder holder as {@link String}
   * @return key as byte-array, <code>null</code> if not found
   * @throws IllegalArgumentException if holder <code>null</code>
   */
  public abstract byte[] getKeyByHolder(String holder);
}

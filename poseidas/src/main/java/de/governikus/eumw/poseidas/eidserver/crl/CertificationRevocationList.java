/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.eidserver.crl;

import java.security.cert.X509CRL;


/**
 * The {@link CertificationRevocationList} interface provides one method to get a {@link X509CRL}
 */
public interface CertificationRevocationList
{

  /**
   * Returns the CRL for the specified URL.
   *
   * @param url url of the CRL
   * @return the {@link X509CRL} of the specified url or null when:
   *         <ul>
   *         <li>the CRL cannot be downloaded</li>
   *         <li>the signature of the CRL cannot be verified</li>
   *         <li>the <code>nextUpdate</code> value of the CRL is already exceeded</li>
   *         <li>the cache time for the CRL is exceeded</li>
   *         </ul>
   */
  X509CRL getX509CRL(String url);
}

/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.eidserver.crl;

import java.security.cert.X509CRL;
import java.util.Set;


/**
 * The CrlCache is meant to store @{@link CrlDao} objects that can be retrieved, put or deleted.
 */
public interface CrlCache
{

  /**
   * Returns the CRL for the specified URL.
   *
   * @param url url of the CRL
   * @return the {@link CrlDao} of the specified url or null when the URL is unknown to the cache
   */
  CrlDao get(String url);

  /**
   * Sets a CRL under the specified key.<br>
   * In case the parameter <code>crl</code> is set to null, the entry for the given <code>url</code> will be
   * deleted from the cache.
   *
   * @param url key at which the specified crl is to be stored, or deleted in case the <code>crl</code>
   *          parameter is set to null
   * @param crl crl to be stored, or null in case the entry should be deleted
   */
  void set(String url, X509CRL crl);

  /**
   * Returns the set of URLs for which CRLs are saved
   *
   * @return the set of URLs for which CRLs are saved
   */
  Set<String> getAvailableUrls();
}

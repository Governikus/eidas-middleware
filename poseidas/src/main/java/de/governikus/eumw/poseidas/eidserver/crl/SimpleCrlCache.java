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

import lombok.extern.slf4j.Slf4j;

import java.security.cert.X509CRL;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;


/**
 * This class is a Simple implementation of CRL Cache with an in memory storage.
 */
@Slf4j
public class SimpleCrlCache implements CrlCache
{

  private final Map<String, CrlDao> storage = new TreeMap<>();

  /**
   * {@inheritDoc}
   */
  @Override
  public CrlDao get(String url)
  {
    return storage.get(url);
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public void set(String url, X509CRL crl)
  {
    if (crl == null)
    {
      log.debug("CRL for URL {} will be removed from the CrlCache", url);
      storage.remove(url);
    }
    else
    {
      log.debug("CRL for URL {} is saved in the CrlCache", url);
      storage.put(url, new CrlDao(crl, System.currentTimeMillis()));
    }
  }

  @Override
  public Set<String> getAvailableUrls()
  {
    return storage.keySet();
  }

}

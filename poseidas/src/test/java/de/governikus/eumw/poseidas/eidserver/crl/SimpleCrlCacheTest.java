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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import com.google.common.collect.Sets;


@DisplayName("The SimpleCrlCache")
class SimpleCrlCacheTest
{

  private static final String HTTP_TEST_URL = "http://test-url.de";

  @Test
  @DisplayName("returns a CRL when the CRL is in the cache")
  void crlCacheReturnsCRLWhenCRLCached()
  {
    SimpleCrlCache simpleCrlCache = new SimpleCrlCache();
    X509CRL mock = Mockito.mock(X509CRL.class);
    simpleCrlCache.set(HTTP_TEST_URL, mock);
    CrlDao crlDao = simpleCrlCache.get(HTTP_TEST_URL);
    Assertions.assertNotNull(crlDao);
    Assertions.assertEquals(mock, crlDao.getX509CRL());
  }

  @Test
  @DisplayName("returns null when the CRL is not in the cache")
  void crlCacheReturnsNullWhenCRLNotCached()
  {
    SimpleCrlCache simpleCrlCache = new SimpleCrlCache();
    CrlDao x509CRL = simpleCrlCache.get(HTTP_TEST_URL);

    Assertions.assertNull(x509CRL);
  }

  @Test
  @DisplayName("removes a crl when set method is called without a CRL")
  void crlCacheRemovesCRLWhenSetCalledWithoutCRL()
  {
    SimpleCrlCache simpleCrlCache = new SimpleCrlCache();
    X509CRL mock = Mockito.mock(X509CRL.class);
    simpleCrlCache.set(HTTP_TEST_URL, mock);
    CrlDao x509CRL = simpleCrlCache.get(HTTP_TEST_URL);
    Assertions.assertNotNull(x509CRL);

    simpleCrlCache.set(HTTP_TEST_URL, null);
    x509CRL = simpleCrlCache.get(HTTP_TEST_URL);

    Assertions.assertNull(x509CRL);
  }

  @Test
  @DisplayName("return all saved URLs")
  void returnAvailableURLs()
  {
    SimpleCrlCache simpleCrlCache = new SimpleCrlCache();
    X509CRL mock = Mockito.mock(X509CRL.class);

    // Add three URLS, remove one
    simpleCrlCache.set(HTTP_TEST_URL, mock);
    String secondHttpTestUrl = HTTP_TEST_URL + "/2";
    simpleCrlCache.set(secondHttpTestUrl, mock);
    String thirdHttpTestUrl = HTTP_TEST_URL + "/3";
    simpleCrlCache.set(thirdHttpTestUrl, mock);
    simpleCrlCache.set(secondHttpTestUrl, null);

    // Check that two URLs are available
    Assertions.assertEquals(2, simpleCrlCache.getAvailableUrls().size());
    Assertions.assertIterableEquals(Sets.newHashSet(HTTP_TEST_URL, thirdHttpTestUrl),
                                    simpleCrlCache.getAvailableUrls());
  }
}

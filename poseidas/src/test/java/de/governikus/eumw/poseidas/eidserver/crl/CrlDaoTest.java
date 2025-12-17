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


@DisplayName("The CrlDao")
class CrlDaoTest
{

  private static final long LAST_UPDATE_TIME_OLDER_24H = System.currentTimeMillis() - 24 * 60 * 60 * 1000;

  private static final long LAST_UPDATE_TIME_WITHIN_24H = System.currentTimeMillis() - 2 * 60 * 60 * 1000;


  @Test
  @DisplayName("returns false when last CRL update was within 24 hours")
  void crlIsNotOlderThan24HoursReturnFalse()
  {
    X509CRL x509CRLMock = Mockito.mock(X509CRL.class);
    CrlDao crlDao = new CrlDao(x509CRLMock, LAST_UPDATE_TIME_WITHIN_24H);
    boolean isCrlOlderThan24Hours = crlDao.isCrlOlderThan24Hours();

    Assertions.assertFalse(isCrlOlderThan24Hours);
  }

  @Test
  @DisplayName("returns true when last CRL update was within 24 hours")
  void crlIsOlderThan24HoursReturnTrue()
  {
    X509CRL x509CRLMock = Mockito.mock(X509CRL.class);
    CrlDao crlDao = new CrlDao(x509CRLMock, LAST_UPDATE_TIME_OLDER_24H);
    boolean isCrlOlderThan24Hours = crlDao.isCrlOlderThan24Hours();

    Assertions.assertTrue(isCrlOlderThan24Hours);
  }
}

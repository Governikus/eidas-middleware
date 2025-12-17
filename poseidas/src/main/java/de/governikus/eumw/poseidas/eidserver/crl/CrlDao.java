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

import lombok.Getter;


/**
 * This class serves as a wrapper for a {@link X509CRL} which additionally stores the UNIX time of the last update of
 * the CRL.
 */
public class CrlDao
{

  @Getter
  private X509CRL x509CRL;

  @Getter
  private final long lastUpdate;

  /**
   * Initializes a new {@link CrlDao} object with a {@link X509CRL} and the time the CRl was updated.
   *
   * @param crl a CRl
   * @param currentTimeMillis time in UNIX format
   */
  public CrlDao(X509CRL crl, long currentTimeMillis)
  {
    this.x509CRL = crl;
    this.lastUpdate = currentTimeMillis;
  }

  /**
   * Checks whether the last time the CRL was updated was more than 24 hours ago.
   *
   * @return is CRL older than 24 hours
   */
  public boolean isCrlOlderThan24Hours()
  {
    return System.currentTimeMillis() >= lastUpdate + 24 * 60 * 60 * 1000;
  }
}

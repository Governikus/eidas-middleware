/*
 * Copyright (c) 2022 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.config.model;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.TimeZone;

import de.governikus.eumw.poseidas.eidserver.crl.CertificationRevocationListImpl;
import de.governikus.eumw.poseidas.server.idprovider.config.CvcTlsCheck;
import lombok.Getter;


/**
 * Model class that holds the global data to be shown on the status page. This class holds all the global information
 * that can be retrieved using SNMP GET calls.
 */
@Getter
public class GlobalResultModel
{

  private boolean serverTlsValid;

  private LocalDateTime tlsValidUntil;

  private boolean crlAvailable;

  private LocalDateTime lastCrlRenewal;

  /**
   * Create the global result model based on the
   * {@link de.governikus.eumw.poseidas.server.idprovider.config.CvcTlsCheck.CvcTlsCheckResult} and data from
   * {@link CertificationRevocationListImpl}
   *
   * @param cvcTlsCheckResult The result of the {@link CvcTlsCheck}
   */
  public GlobalResultModel(CvcTlsCheck.CvcTlsCheckResult cvcTlsCheckResult)
  {
    this.serverTlsValid = cvcTlsCheckResult.isServerTlsValid();
    this.crlAvailable = CertificationRevocationListImpl.isInitialized();

    if (cvcTlsCheckResult.getServerTlsExpirationDate() != null)
    {
      this.tlsValidUntil = cvcTlsCheckResult.getServerTlsExpirationDate()
                                            .toInstant()
                                            .atZone(ZoneId.systemDefault())
                                            .toLocalDateTime();
    }

    if (crlAvailable)
    {
      long latestRetrieval = CertificationRevocationListImpl.latestRetrieval();
      if (latestRetrieval != 0)
      {
        this.lastCrlRenewal = LocalDateTime.ofInstant(Instant.ofEpochMilli(latestRetrieval),
                                                      TimeZone.getDefault().toZoneId());
      }
    }
  }
}

/*
 * Copyright (c) 2022 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.pki;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.Optional;

import org.springframework.stereotype.Service;

import de.governikus.eumw.config.ServiceProviderType;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.CertificateDescription;
import de.governikus.eumw.poseidas.config.model.ServiceProviderStatus;
import de.governikus.eumw.poseidas.server.idprovider.config.CvcTlsCheck;
import lombok.extern.slf4j.Slf4j;


@Slf4j
@Service
public class ServiceProviderStatusService
{

  private final TerminalPermissionAOBean facade;

  private final CvcTlsCheck cvcTlsCheck;

  private final PermissionDataHandlingMBean permissionDataHandling;

  private final RequestSignerCertificateService rscService;

  public ServiceProviderStatusService(TerminalPermissionAOBean facade,
                                      CvcTlsCheck cvcTlsCheck,
                                      PermissionDataHandlingMBean permissionDataHandling,
                                      RequestSignerCertificateService rscService)
  {
    this.facade = facade;
    this.cvcTlsCheck = cvcTlsCheck;
    this.permissionDataHandling = permissionDataHandling;
    this.rscService = rscService;
  }

  public ServiceProviderStatus getServiceProviderStatus(ServiceProviderType serviceProviderType)
  {
    ServiceProviderStatus.ServiceProviderStatusBuilder builder = ServiceProviderStatus.builder()
                                                                                      .serviceProviderName(serviceProviderType.getName())
                                                                                      .enabled(serviceProviderType.isEnabled());

    TerminalPermission terminalPermission = facade.getTerminalPermission(serviceProviderType.getCVCRefID());
    if (terminalPermission == null)
    {
      // there is no terminal permission present, therefore no data to be shown in the status page
      return builder.build();
    }

    CvcTlsCheck.CvcCheckResults cvcCheckResults = cvcTlsCheck.checkCvcProvider(serviceProviderType.getName());

    boolean cvcPresent = cvcCheckResults.isCvcPresent();
    if (cvcPresent)
    {
      builder.cvcPresent(true)
             .cvcValidUntil(Optional.ofNullable(dateToLocalDate(terminalPermission.getNotOnOrAfter()))
                                    .map(d -> d.minusDays(1))
                                    .orElse(null))
             .cvcValidity(cvcCheckResults.isCvcValidity())
             .cvcTLSLinkStatus(cvcCheckResults.isCvcTlsMatch())
             .cvcUrlMatch(cvcCheckResults.isCvcUrlMatch());
      if (terminalPermission.getCvcDescription() != null)
      {
        try
        {
          builder.cvcSubjectUrl(new CertificateDescription(terminalPermission.getCvcDescription()).getSubjectUrl());
        }
        catch (IOException e)
        {
          log.debug("Cannot read subject URL from CVC description", e);
        }
      }
    }
    builder.blackListPresent(terminalPermission.getBlackListVersion() != null)
           .blackListLastRetrieval(dateToLocalDateTime(terminalPermission.getBlackListStoreDate()))
           .blackListDVCAAvailability(permissionDataHandling.pingRIService(serviceProviderType.getName()))
           .masterListPresent(terminalPermission.getMasterListStoreDate() != null)
           .masterListLastRetrieval(dateToLocalDateTime(terminalPermission.getMasterListStoreDate()))
           .masterListDVCAAvailability(permissionDataHandling.pingPAService(serviceProviderType.getName()))
           .defectListPresent(terminalPermission.getDefectListStoreDate() != null)
           .defectListLastRetrieval(dateToLocalDateTime(terminalPermission.getDefectListStoreDate()))
           .defectListDVCAAvailability(permissionDataHandling.pingPAService(serviceProviderType.getName()));

    X509Certificate pendingRSC = rscService.getRequestSignerCertificate(serviceProviderType.getName(), false);
    if (pendingRSC != null)
    {
      builder.rscPendingPresent(true).rscAnyPresent(true);
    }
    X509Certificate currentRSC = rscService.getRequestSignerCertificate(serviceProviderType.getName(), true);
    if (currentRSC != null)
    {
      builder.rscCurrentValidUntil(dateToLocalDate(currentRSC.getNotAfter())).rscAnyPresent(true);
    }

    return builder.build();
  }

  private LocalDate dateToLocalDate(Date date)
  {
    if (date == null)
    {
      return null;
    }
    return date.toInstant().atZone(ZoneId.systemDefault()).toLocalDate();
  }

  private LocalDateTime dateToLocalDateTime(Date date)
  {
    if (date == null)
    {
      return null;
    }
    return date.toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime();
  }

}

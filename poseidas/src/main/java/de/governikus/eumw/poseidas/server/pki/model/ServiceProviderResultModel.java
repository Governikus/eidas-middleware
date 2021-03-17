/*
 * Copyright (c) 2021 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.pki.model;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;

import de.governikus.eumw.poseidas.cardbase.asn1.npa.CertificateDescription;
import de.governikus.eumw.poseidas.server.idprovider.config.CvcTlsCheck;
import de.governikus.eumw.poseidas.server.idprovider.config.PoseidasConfigurator;
import de.governikus.eumw.poseidas.server.pki.PermissionDataHandlingMBean;
import de.governikus.eumw.poseidas.server.pki.RequestSignerCertificateService;
import de.governikus.eumw.poseidas.server.pki.TerminalPermission;
import de.governikus.eumw.poseidas.server.pki.TerminalPermissionAO;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;


/**
 * Model class that holds the service provider specific data to be shown on the status page. This class holds all the
 * provider specific information that can be retrieved using SNMP GET calls.
 */
@Slf4j
@Getter
public class ServiceProviderResultModel
{

  private String serviceProviderName;

  private boolean cvcPresent;

  private LocalDate cvcValidUntil;

  private String cvcSubjectUrl;

  private boolean cvcTLSLinkStatus;

  private boolean blackListPresent;

  private LocalDateTime blackListLastRetrieval;

  private boolean blackListDVCAAvailability;

  private boolean masterListPresent;

  private LocalDateTime masterListLastRetrieval;

  private boolean masterListDVCAAvailability;

  private boolean defectListPresent;

  private LocalDateTime defectListLastRetrieval;

  private boolean defectListDVCAAvailability;

  private boolean rscPendingPresent;

  private LocalDate rscCurrentValidUntil;

  /**
   * Create an object for the given service provider using the cvcTlsCheckResult and the other data sources. If there is
   * no terminal permission entry available, e.g. the service provider exists only in the config but no cvc requests
   * were made, all non-primitive fields will be null.
   *
   * @param serviceProviderName The service provider whose data should be gathered
   * @param cvcTlsCheckResult The result of the {@link CvcTlsCheck} for this service provider
   * @param facade The {@link TerminalPermissionAO} instance to access the service provider's data
   * @param permissionDataHandling The {@link PermissionDataHandlingMBean} instance to trigger the connection checks to
   *          the DVCA
   */
  public ServiceProviderResultModel(String serviceProviderName,
                                    CvcTlsCheck.CvcCheckResults cvcTlsCheckResult,
                                    TerminalPermissionAO facade,
                                    PermissionDataHandlingMBean permissionDataHandling,
                                    RequestSignerCertificateService rscService)
  {
    String cvcRefID = PoseidasConfigurator.getInstance()
                                          .getCurrentConfig()
                                          .getServiceProvider()
                                          .get(serviceProviderName)
                                          .getEpaConnectorConfiguration()
                                          .getCVCRefID();
    TerminalPermission terminalPermission = facade.getTerminalPermission(cvcRefID);
    if (terminalPermission == null)
    {
      // there is no terminal permission present, therefore no data to be shown in the status page
      return;
    }

    this.serviceProviderName = serviceProviderName;
    this.cvcPresent = cvcTlsCheckResult.isCvcPresent();
    LocalDate cvcNotOnOrAfter = dateToLocalDate(terminalPermission.getNotOnOrAfter());
    if (cvcNotOnOrAfter != null)
    {
      this.cvcValidUntil = cvcNotOnOrAfter.minusDays(1);
    }
    this.cvcTLSLinkStatus = cvcTlsCheckResult.isCvcTlsMatch();
    this.blackListPresent = terminalPermission.getBlackListVersion() != null;
    this.blackListLastRetrieval = dateToLocalDateTime(terminalPermission.getBlackListStoreDate());
    this.blackListDVCAAvailability = permissionDataHandling.pingRIService(serviceProviderName);
    this.masterListPresent = terminalPermission.getMasterList() != null;
    this.masterListLastRetrieval = dateToLocalDateTime(terminalPermission.getMasterListStoreDate());
    this.masterListDVCAAvailability = permissionDataHandling.pingPAService(serviceProviderName);
    this.defectListPresent = terminalPermission.getDefectList() != null;
    this.defectListLastRetrieval = dateToLocalDateTime(terminalPermission.getDefectListStoreDate());
    this.defectListDVCAAvailability = permissionDataHandling.pingPAService(serviceProviderName);
    this.rscPendingPresent = rscService.getRequestSignerCertificate(serviceProviderName, false) != null;
    X509Certificate requestSignerCertificate = rscService.getRequestSignerCertificate(serviceProviderName, true);
    if (requestSignerCertificate != null)
    {
      this.rscCurrentValidUntil = dateToLocalDate(requestSignerCertificate.getNotAfter());
    }
    if (terminalPermission.getCvcDescription() != null)
    {
      try
      {
        this.cvcSubjectUrl = new CertificateDescription(terminalPermission.getCvcDescription()).getSubjectUrl();
      }
      catch (IOException e)
      {
        log.warn("Cannot read subject URL from CVC description", e);
      }
    }
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

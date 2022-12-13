/*
 * Copyright (c) 2022 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.config.model;

import java.time.LocalDate;
import java.time.LocalDateTime;

import lombok.Builder;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;


/**
 * Model class that holds the service provider specific data to be shown on the status page. This class holds all the
 * provider specific information that can be retrieved using SNMP GET calls.
 */
@Slf4j
@Getter
@Builder
public class ServiceProviderStatus
{

  private String serviceProviderName;

  private boolean cvcPresent;

  private LocalDate cvcValidUntil;

  private boolean cvcValidity;

  private String cvcSubjectUrl;

  private boolean cvcTLSLinkStatus;

  private boolean cvcUrlMatch;

  private boolean blackListPresent;

  private LocalDateTime blackListLastRetrieval;

  private boolean blackListDVCAAvailability;

  private boolean masterListPresent;

  private LocalDateTime masterListLastRetrieval;

  private boolean masterListDVCAAvailability;

  private boolean defectListPresent;

  private LocalDateTime defectListLastRetrieval;

  private boolean defectListDVCAAvailability;

  private boolean rscAnyPresent;

  private boolean rscPendingPresent;

  private LocalDate rscCurrentValidUntil;

  private boolean enabled;

}

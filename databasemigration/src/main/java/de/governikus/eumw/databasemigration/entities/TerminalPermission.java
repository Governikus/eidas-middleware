/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.databasemigration.entities;

import java.io.Serializable;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import jakarta.annotation.Nullable;
import jakarta.persistence.CascadeType;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.Lob;
import jakarta.persistence.OneToMany;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Temporal;
import jakarta.persistence.TemporalType;

import lombok.Data;


@Entity
@Data
public class TerminalPermission implements Serializable
{

  private static final long serialVersionUID = 8085421165844034269L * 5;

  @Id
  private String refID;

  // Cascade set to ALL instead of REMOVE to allow for automatic saving
  @OneToOne(cascade = CascadeType.ALL)
  @JoinColumn(name = "refID", updatable = false)
  private PendingCertificateRequest pendingRequest;

  @Lob
  private byte[] cvc;

  @Lob
  private byte[] cvcDescription;

  @Lob
  private byte[] cvcPrivateKey;

  @Lob
  private byte[] riKey1;

  @Lob
  private byte[] psKey;

  @Lob
  private byte[] sectorID;

  @Temporal(TemporalType.TIMESTAMP)
  private Date notOnOrAfter;

  // Cascade set to ALL instead of REMOVE to allow for automatic saving
  @OneToMany(mappedBy = "terminalPermission", cascade = CascadeType.ALL, fetch = FetchType.EAGER)
  private Set<CertInChain> chain;

  @Lob
  private byte[] masterList;

  @Temporal(TemporalType.TIMESTAMP)
  private Date masterListStoreDate;

  @Lob
  private byte[] defectList;

  @Temporal(TemporalType.TIMESTAMP)
  private Date defectListStoreDate;

  @Temporal(TemporalType.TIMESTAMP)
  private Date blackListStoreDate;

  private Long blackListVersion;

  private String rscChr;

  @OneToOne(cascade = CascadeType.ALL)
  private RequestSignerCertificate currentRequestSignerCertificate;

  @OneToOne(cascade = CascadeType.ALL)
  private RequestSignerCertificate pendingRequestSignerCertificate;

  /**
   * Constructor needed by hibernate
   */
  public TerminalPermission()
  {
    // nothing to do here
  }

  /**
   * Create an instance setting the always requested attributes
   *
   * @param refID artificial primary key
   */
  public TerminalPermission(String refID)
  {
    super();
    this.refID = refID;
    chain = new HashSet<>();
  }

}

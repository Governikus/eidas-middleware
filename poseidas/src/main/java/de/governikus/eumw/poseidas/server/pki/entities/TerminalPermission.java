/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.pki.entities;

import java.io.IOException;
import java.io.Serializable;
import java.util.Date;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import jakarta.annotation.Nullable;
import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.Lob;
import jakarta.persistence.OneToMany;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Temporal;
import jakarta.persistence.TemporalType;

import de.governikus.eumw.poseidas.eidmodel.TerminalData;
import lombok.Data;


/**
 * Entity to persist the terminal permission data needed to access an ePA. That data contains the access data for the
 * PKI which issues the terminal certificates as well because it is needed in the renewal process.
 *
 * @author TT
 */
@Entity
@Data
public class TerminalPermission implements Serializable
{

  private static final long serialVersionUID = 8085421165844034269L * 5;

  @Id
  private String refID;

  @OneToOne(cascade = CascadeType.REMOVE)
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

  @OneToMany(mappedBy = "terminalPermission", cascade = CascadeType.REMOVE, fetch = FetchType.EAGER)
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
   * Holds the sequence number to use next for a CVC request. Nullable because field was added lately and could stay
   * undefined through migration.
   */
  @Nullable
  private Integer nextCvcSequenceNumber;

  @Column(columnDefinition = "boolean default false")
  private boolean automaticCvcRenewFailed;

  private String automaticRscRenewFailed;

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

  /**
   * Return null if all attributes are filled, a message otherwise.
   */
  private String reportMissingAttribute()
  {
    if (cvc == null)
    {
      return "no CVC data found";
    }
    if (cvc.length < 10)
    {
      return "CVC data truncated";
    }
    if (cvcDescription == null)
    {
      return "no certificate description data found";
    }
    if (cvcDescription.length < 10)
    {
      return "certificate description truncated";
    }
    if (riKey1 == null)
    {
      return "no public sector key found";
    }
    if (chain == null)
    {
      return "no certificate chain found";
    }
    if (chain.isEmpty())
    {
      return "certificate chain is empty";
    }
    return null;
  }

  /**
   * @return data Object containing all needed values except blacklist
   * @throws IllegalArgumentException
   */
  public TerminalData getFullCvc()
  {
    String problem = reportMissingAttribute();
    if (problem != null)
    {
      throw new IllegalArgumentException("CVC data not configured correctly: " + problem);
    }
    try
    {
      return new TerminalData(cvc, cvcDescription, cvcPrivateKey, riKey1, psKey);
    }
    catch (IOException e)
    {
      throw new IllegalArgumentException("unable to parse given CVC", e);
    }
  }

  public List<TerminalData> getCvcChain()
  {
    List<TerminalData> result = new LinkedList<>();
    for ( CertInChain elem : chain )
    {
      try
      {
        result.add(new TerminalData(elem.getData()));
      }
      catch (IOException e)
      {
        throw new IllegalArgumentException("unable to parse given cvc", e);
      }
    }
    return result;
  }

  public void increaseSequenceNumber()
  {
    if (nextCvcSequenceNumber == null)
    {
      return;
    }

    if (nextCvcSequenceNumber == 99999)
    {
      nextCvcSequenceNumber = 1;
    }
    else
    {
      nextCvcSequenceNumber++;
    }
  }

  @Override
  public int hashCode()
  {
    return refID.hashCode();
  }

  @Override
  public boolean equals(Object obj)
  {
    if (this == obj)
    {
      return true;
    }
    if (obj instanceof TerminalPermission tp)
    {
      return refID.equals(tp.refID);
    }
    return false;
  }
}

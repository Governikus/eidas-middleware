/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.pki;

import java.io.IOException;
import java.io.Serializable;
import java.util.Date;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import javax.persistence.CascadeType;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.Lob;
import javax.persistence.NamedQueries;
import javax.persistence.NamedQuery;
import javax.persistence.OneToMany;
import javax.persistence.OneToOne;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;

import de.governikus.eumw.poseidas.eidmodel.TerminalData;



/**
 * Entity to persist the terminal permission data needed to access an ePA. That data contains the access data
 * for the PKI which issues the terminal certificates as well because it is needed in the renewal process.
 * 
 * @author TT
 */
@Entity
@NamedQueries({
               @NamedQuery(name = "getTerminalPermissionList", query = "SELECT t FROM TerminalPermission t ORDER BY t.notOnOrAfter"),
               @NamedQuery(name = "getByMessageId", query = "SELECT t FROM TerminalPermission t WHERE t.pendingRequest.messageID = :pMessageID")})
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

  @OneToMany(mappedBy = "terminalPermission", cascade = CascadeType.REMOVE)
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
  TerminalPermission(String refID)
  {
    super();
    this.refID = refID;
    chain = new HashSet<>();
  }

  /**
   * Return the currently active terminal access certificate
   */
  public byte[] getCvc()
  {
    return cvc;
  }

  /**
   * @see #getCvc()
   */
  public void setCvc(byte[] cvc)
  {
    this.cvc = cvc;
  }

  /**
   * Return the description (additional information needed for using the cvc with an nPA)
   */
  public byte[] getCvcDescription()
  {
    return cvcDescription;
  }

  /**
   * @see #getCvcDescription()
   */
  public void setCvcDescription(byte[] cvcDescription)
  {
    this.cvcDescription = cvcDescription;
  }

  /**
   * Return the private key for the CVS (PKCS#8, but encrypted)
   */
  public byte[] getCvcPrivateKey()
  {
    return cvcPrivateKey;
  }

  /**
   * @see #setCvcPrivateKey(byte[])
   */
  public void setCvcPrivateKey(byte[] cvcPrivateKey)
  {
    this.cvcPrivateKey = cvcPrivateKey;
  }

  /**
   * Return the expiry date of the CVC
   */
  public Date getNotOnOrAfter()
  {
    return notOnOrAfter;
  }

  /**
   * @see #setNotOnOrAfter(Date)
   */
  public void setNotOnOrAfter(Date notOnOrAfter)
  {
    this.notOnOrAfter = notOnOrAfter;
  }

  /**
   * Return the artificial primary key
   */
  public String getRefID()
  {
    return refID;
  }

  /**
   * Return all Attributes defined for that user.
   */
  public Set<CertInChain> getChain()
  {
    return chain;
  }

  /**
   * Return the key for generation of the restricted ID (pseudonym).
   */
  public byte[] getRiKey1()
  {
    return riKey1;
  }

  /**
   * @see #getRiKey1()
   */
  public void setRiKey1(byte[] riKey1)
  {
    this.riKey1 = riKey1;
  }

  /**
   * Return the key for pseudonymous signatures.
   */
  public byte[] getPSKey()
  {
    return psKey;
  }

  /**
   * Set the key for pseudonymous signatures.
   */
  public void setPSKey(byte[] psKey)
  {
    this.psKey = psKey;
  }
  
  /**
   * Return information about a certificate request which has been created but not yet answered by the trust
   * center - you may want to send this request again.
   */
  public PendingCertificateRequest getPendingCertificateRequest()
  {
    return pendingRequest;
  }

  /**
   * @see #getPendingCertificateRequest()
   */
  public void setPendingCertificateRequest(PendingCertificateRequest request)
  {
    pendingRequest = request;
  }

  /**
   * Returns the sector ID of this service provider. This id came from the blacklist.
   */
  public byte[] getSectorID()
  {
    return sectorID;
  }

  /**
   * @see #getSectorID()
   */
  public void setSectorID(byte[] sectorID)
  {
    this.sectorID = sectorID;
  }

  /**
   * Returns the master list for this service provider.
   */
  public byte[] getMasterList()
  {
    return masterList;
  }

  /**
   * @see #getMasterList()
   */
  public void setMasterList(byte[] masterList)
  {
    this.masterList = masterList;
  }

  /**
   * Returns the date when the master list was stored.
   */
  public Date getMasterListStoreDate()
  {
    return masterListStoreDate;
  }

  /**
   * @see #getMasterListStoreDate()
   */
  public void setMasterListStoreDate(Date masterListStoreDate)
  {
    this.masterListStoreDate = masterListStoreDate;
  }

  /**
   * Returns the defect list for this service provider.
   */
  public byte[] getDefectList()
  {
    return defectList;
  }

  /**
   * @see #getDefectList()
   */
  public void setDefectList(byte[] defectList)
  {
    this.defectList = defectList;
  }

  /**
   * Returns the date when the defect list was stored.
   */
  public Date getDefectListStoreDate()
  {
    return defectListStoreDate;
  }

  /**
   * @see #getDefectListStoreDate()
   */
  public void setDefectListStoreDate(Date defectListStoreDate)
  {
    this.defectListStoreDate = defectListStoreDate;
  }

  public Date getBlackListStoreDate()
  {
    return blackListStoreDate;
  }

  public void setBlackListStoreDate(Date blackListStoreDate)
  {
    this.blackListStoreDate = blackListStoreDate;
  }

  /**
   * Gets the blacklist ID.
   *
   * @return blacklist ID
   */
  public Long getBlackListVersion()
  {
    return blackListVersion;
  }

  /**
   * Sets the blacklist ID.
   *
   * @param blackListVersion ID
   */
  public void setBlackListVersion(Long blackListVersion)
  {
    this.blackListVersion = blackListVersion;
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
      throw new IllegalArgumentException("unable to parse given cvc", e);
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
}

/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.pki;

import java.io.Serializable;
import java.util.Date;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Lob;
import jakarta.persistence.Temporal;
import jakarta.persistence.TemporalType;


/**
 * Holds certificate request data of requests which have been created but not yet answered. You might want to send these
 * request again or take other steps.
 *
 * @author tautenhahn
 */
@Entity
public class PendingCertificateRequest implements Serializable
{

  private static final long serialVersionUID = 7011177849844700896L;

  /**
   * Status values describing the step within the certificate download process.
   */
  public enum Status
  {
    /** request has been created - private key is in HSM (in database for test only) */
    CREATED,
    /** request has been sent and accepted by the BerCA service */
    SENT,
    /**
     * one step of the request process failed and some administrator should intervene - see additional info
     */
    FAILURE
  }

  @Id
  private String refID;

  @Lob
  private byte[] requestData;

  @Lob
  private byte[] privateKey;

  @Enumerated(EnumType.STRING)
  private Status status;

  @Column(length = 1024)
  private String additionalInfo;

  private String messageID;

  @Temporal(TemporalType.TIMESTAMP)
  private Date lastChanged;

  @Lob
  private byte[] newCvcDescription;

  /**
   * Used to check if this pending request may be sent again.
   */
  @Column(columnDefinition = "boolean default false")
  private boolean canBeSentAgain;


  /**
   * needed for JPA, do not use!
   */
  public PendingCertificateRequest()
  {
    // nothing to do here
  }


  /**
   * Create new instance to represent a request created now.
   *
   * @param refID specified the permission data record this request belongs to
   */
  PendingCertificateRequest(String refID)
  {
    this.refID = refID;
    status = Status.CREATED;
    lastChanged = new Date();
  }

  /**
   * Return the primary key
   */
  public String getRefID()
  {
    return refID;
  }

  /**
   * return certificate request data
   */
  public byte[] getRequestData()
  {
    return requestData;
  }

  /**
   * return PK, null if PK is stored inside HSM
   */
  public byte[] getPrivateKey()
  {
    return privateKey;
  }

  /**
   * @see #getRequestData()
   * @param requestData
   */
  public void setRequestData(byte[] requestData)
  {
    this.requestData = requestData;
  }

  /**
   * @see #getPrivateKey()
   * @param privateKey
   */
  public void setPrivateKey(byte[] privateKey)
  {
    this.privateKey = privateKey;
  }

  /**
   * Return status of request
   */
  public Status getStatus()
  {
    return status;
  }

  /**
   * update the status
   */
  public void setStatus(Status status)
  {
    this.status = status;
    lastChanged = new Date();
  }

  /**
   * Return date of last change
   */
  public Date getLastChanged()
  {
    return lastChanged;
  }

  /**
   * set the messageID of a pending request - needed for assigning asynchronously obtained data
   *
   * @param messageID
   */
  public void setMessageID(String messageID)
  {
    this.messageID = messageID;
  }

  /**
   * Return the messageID under which the request was sent.
   */
  public String getMessageID()
  {
    return messageID;
  }

  /**
   * Return the new cvc description for this pending request.
   */
  public byte[] getNewCvcDescription()
  {
    return newCvcDescription;
  }

  /**
   * Add a new CVC description to this pending request.
   *
   * @param newCvcDescription
   */
  public void setNewCvcDescription(byte[] newCvcDescription)
  {
    this.newCvcDescription = newCvcDescription;
  }

  /**
   * set an optional free String which contains additional information about the current status of the request.
   * Interpretation is totally up to the the administrator, poseidas will not use this value.
   *
   * @param additionalInfo
   */
  public void setAdditionalInfo(String additionalInfo)
  {
    this.additionalInfo = additionalInfo;
  }

  /**
   * @see PendingCertificateRequest#setAdditionalInfo(String)
   */
  public String getAdditionalInfo()
  {
    return additionalInfo;
  }

  /**
   * Defines if this pending request may be sent again.
   * 
   * @return
   */
  public boolean isCanBeSentAgain()
  {
    return canBeSentAgain;
  }

  /**
   * Set if this pending request may be sent again.
   * 
   * @param canBeSentAgain new value
   */
  public void setCanBeSentAgain(boolean canBeSentAgain)
  {
    this.canBeSentAgain = canBeSentAgain;
  }
}

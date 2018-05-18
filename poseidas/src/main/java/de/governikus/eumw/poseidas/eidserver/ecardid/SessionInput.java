/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.eidserver.ecardid;

import java.io.Serializable;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;

import de.governikus.eumw.poseidas.cardbase.asn1.npa.ATEidAccess.AccessRightEnum;
import de.governikus.eumw.poseidas.eidmodel.TerminalData;
import de.governikus.eumw.poseidas.eidmodel.data.EIDKeys;
import de.governikus.eumw.poseidas.eidserver.convenience.CAConnection;


/**
 * Interface for the interface between eID-Server ant the eCard API convenience layer. The EID-Server provides
 * an implementation of this interface that provides the information given.
 * 
 * @author Alexander Funk
 * @author <a href="mail:hme@bos-bremen.de">Hauke Mehrtens</a>
 **/
public interface SessionInput extends Serializable
{

  /**
   * Return the required age (> 0) if age verification should be performed
   * 
   * @return null if not
   */
  public abstract Integer getRequiredAge();

  /**
   * Return the required community ID if place verification should be performed <br>
   * 
   * @return null if not or required communityID as String "02 76 XX 0X XX 0X XX" <br>
   *         02 76 - Deutschland <br>
   *         &nbsp;&nbsp;&nbsp;XX - Bundesland <br>
   *         0X XX - Regierungsbezirk/Landkreis<br>
   *         0X XX - Gemeinde<br>
   */
  public abstract String getRequiredCommunity();

  /**
   * Return true if document validity should be verified.
   */
  public abstract boolean isVerifyDocumentValidity();

  /**
   * Return true if restrictedID should be returned.
   */
  public abstract boolean isPerformRestrictedIdentification();

  /**
   * Return the set of all fields which are required by the server. Use this information to create the
   * RequiredCHAT. Furthermore, this information should be used together with {@link #getOptionalFields()} to
   * build the DataSetToBeRead.
   */
  public abstract Set<EIDKeys> getRequiredFields();

  /**
   * Return the set of all fields which are requested but not required by the server. Use this information to
   * create the OptionalCHAT. Furthermore, this information should be used together with
   * {@link #getRequiredFields()} to build the DataSetToBeRead.
   */
  public abstract Set<EIDKeys> getOptionalFields();

  /**
   * Return the list with all Certificates expect the terminal certificate to build the chain: DV certificate
   * and all link certificates.
   * 
   * @return list with all used certificates in chain except the root certificate
   */
  public abstract List<TerminalData> getCvcChain();

  /**
   * Returns the Terminal certificate.
   */
  public abstract TerminalData getTerminalCertificate();

  /**
   * Return the pre-shared key to be used in the PAOS HTTPs communication. Feel free to change the result type
   * of this method to something more suitable.
   */
  public abstract byte[] getPresharedKey();

  /**
   * Return a unique session ID
   */
  public abstract String getSessionID();

  /**
   * HTTPS address for refresh mechanism
   * 
   * @return address as string
   */
  public abstract String getRefreshAddress();

  /**
   * Address for the client to connect to in case of communication error.
   * 
   * @return communication error address
   */
  public abstract String getCommunicationErrorAddress();

  /**
   * Address for the client to connect to the eID-Server
   * 
   * @return address as string
   */
  public abstract String getServerAddress();

  /**
   * Return the blacklist access object - will work even if black list is big
   */
  public abstract BlackListConnector getBlackListConnector();

  /**
   * Returns the SHA256ofSAMLRequest as a binary byte array. This will be included inside the object tag
   */
  @Deprecated
  public abstract byte[] getSHA256ofSAMLRequest();

  /**
   * Returns the Master List which should be used for this Session. If you have a zip or any other method of
   * providing these certificates use {@link #getMasterListCerts()}. If you have a normal master list use this
   * method.
   */
  public abstract byte[] getMasterList();

  /**
   * Provide a list of certificates which should be treated as the master list, this could be used when you
   * have a zip file with valid certificates. In normal cases you should use {@link #getMasterList()}.
   */
  public abstract List<X509Certificate> getMasterListCerts();

  /**
   * Returns the Defect List which should be used for this Session.
   */
  public abstract byte[] getDefectList();

  /**
   * Get the (optional) transaction info.
   * 
   * @return transaction info, <code>null</code> if not present
   */
  public abstract String getTransactionInfo();

  /**
   * Returns the prefix which should be added in front of all log outputs.
   */
  public abstract String getLogPrefix();

  /**
   * Gets the connection to the QES CA (only required if a QES cert is to be generated).
   * 
   * @return
   */
  public abstract CAConnection getCAConnection();

  /**
   * Gets message to be signed by PSM, if applicable.
   * 
   * @return
   */
  public abstract byte[] getPsMessage();

  /**
   * Gets list of file IDs to be included in PSC, if applicable.
   * 
   * @return
   */
  public abstract List<byte[]> getPscFidList();

  /**
   * Gets set of access rights for PSC.
   * 
   * @return
   */
  public abstract Set<AccessRightEnum> getPscAccessRightSet();

  /**
   * Get information whether to include specific attributes in PSC.
   * 
   * @return
   */
  public abstract boolean isPscIncludeSpecific();

  /**
   * Get information whether to access all specific attributes, not just the own.
   * 
   * @return
   */
  public abstract boolean isAccessAllSpecificAttributes();

  /**
   * Gets specific attribute requests.
   * 
   * @return
   */
  public abstract byte[] getSpecificRequests();
}

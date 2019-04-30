/*
 * Copyright (c) 2019 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.eidservice;

import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import de.governikus.eumw.poseidas.eidmodel.TerminalData;
import de.governikus.eumw.poseidas.eidmodel.data.EIDKeys;
import de.governikus.eumw.poseidas.eidserver.ecardid.BlackListConnector;
import de.governikus.eumw.poseidas.eidserver.ecardid.SessionInput;


/**
 * Wrapper for all information needed to build the eCard API dialog. The getters should reveal all information
 * required to build the EACSessionInputType object which is needed by the eCard API (see BSI TR-03112-7 page
 * 39). This is part of the eCardAPIs interface but AF does not want an interface which can be used without
 * defining extra classes.
 *
 * @author tt
 */
public class SessionInputImpl implements SessionInput
{

  private static final long serialVersionUID = 1L;

  // Start of getters: these are to be called by the convenience layer

  /**
   * Return the required age if age verification should be performed
   *
   * @return null if not
   */
  @Override
  public Integer getRequiredAge()
  {
    return requiredAge;
  }

  /**
   * Return the required community ID if place verification should be performed
   *
   * @return null if not
   */
  @Override
  public String getRequiredCommunity()
  {
    return requiredCommunity;
  }

  /**
   * Return true if document validity should be verified.
   */
  @Override
  public boolean isVerifyDocumentValidity()
  {
    return verifyDocumentValidity;
  }

  /**
   * Return true if restrictedID should be returned.
   */
  @Override
  public boolean isPerformRestrictedIdentification()
  {
    return performRestrictedIdentification;
  }

  /**
   * Return the set of all fields which are required by the server. Use this information to create the
   * RequiredCHAT. Furthermore, this information should be used together with {@link #getOptionalFields()} to
   * build the DataSetToBeRead. <br>
   * WARNING: by request of ET this field contains also the keys for verification and requestedID which by
   * statement of JW must not included into any chat object!
   */
  @Override
  public Set<EIDKeys> getRequiredFields()
  {
    return requiredFields;
  }

  /**
   * Return the set of all fields which are requested but not required by the server. Use this information to
   * create the OptionalCHAT. Furthermore, this information should be used together with
   * {@link #getRequiredFields()} to build the DataSetToBeRead. <br>
   * WARNING: by request of ET this field contains also the keys for verification and requestedID which by
   * statement of JW must not included into any chat object!
   */
  @Override
  public Set<EIDKeys> getOptionalFields()
  {
    return optionalFields;
  }

  /**
   * Return a unique session ID. The eCardAPI does not define any restrictions for this value but might
   * require some. (length, format ...)
   */
  @Override
  public String getSessionID()
  {
    return sessionID;
  }

  /**
   * return access object for black list
   */
  @Override
  public BlackListConnector getBlackListConnector()
  {
    return blackListConnector;
  }

  /** {@inheritDoc} */
  @Override
  public String getTransactionInfo()
  {
    return this.transactionInfo;
  }

  // End of getters

  // start of setters: to be used by the server application (and tests)

  /**
   * Create new instance giving the CVC, pre-shared key and sessionID
   */
  private SessionInputImpl(TerminalData cvc,
                           List<TerminalData> cvcChain,
                           String sessionID,
                           BlackListConnector blackListConnector,
                           String refreshAddress,
                           String serverAddress,
                           byte[] masterList,
                           List<X509Certificate> masterListCerts,
                           byte[] defectedList,
                           String transactionInfo,
                           String logPrefix)
  {
    super();
    this.cvc = cvc;
    this.cvcChain = cvcChain;
    this.sessionID = sessionID;
    this.blackListConnector = blackListConnector;
    this.refreshAddress = refreshAddress;
    this.serverAddress = serverAddress;
    this.masterList = masterList;
    this.masterListCerts = masterListCerts;
    this.defectedList = defectedList;
    this.transactionInfo = transactionInfo;
    this.logPrefix = logPrefix;
  }

  /**
   * Create new instance giving the CVC, pre-shared key and sessionID
   */
  SessionInputImpl(TerminalData cvc,
                   List<TerminalData> cvcChain,
                   String sessionID,
                   BlackListConnector blackListConnector,
                   String refreshAddress,
                   String serverAddress,
                   byte[] masterList,
                   byte[] defectedList,
                   String transactionInfo,
                   String logPrefix)
  {
    this(cvc, cvcChain, sessionID, blackListConnector, refreshAddress, serverAddress, masterList, null,
         defectedList, transactionInfo, logPrefix);
  }

  /**
   * Create new instance giving the CVC, pre-shared key and sessionID
   */
  SessionInputImpl(TerminalData cvc,
                   List<TerminalData> cvcChain,
                   String sessionID,
                   BlackListConnector blackListConnector,
                   String refreshAddress,
                   String serverAddress,
                   List<X509Certificate> masterListCerts,
                   byte[] defectedList,
                   String transactionInfo,
                   String logPrefix)
  {
    this(cvc, cvcChain, sessionID, blackListConnector, refreshAddress, serverAddress, null, masterListCerts,
         defectedList, transactionInfo, logPrefix);
  }

  /**
   * Request an age verification
   *
   * @param age
   */
  void setAgeVerification(int age, boolean required)
  {
    requiredAge = Integer.valueOf(age);
    if (required)
    {
      requiredFields.add(EIDKeys.AGE_VERIFICATION);
    }
    else
    {
      optionalFields.add(EIDKeys.AGE_VERIFICATION);
    }
  }

  /**
   * request a place verification
   *
   * @param value
   */
  void setCommunityIDVerification(String value, boolean required)
  {
    requiredCommunity = value;
    if (required)
    {
      requiredFields.add(EIDKeys.MUNICIPALITY_ID_VERIFICATION);
    }
    else
    {
      optionalFields.add(EIDKeys.MUNICIPALITY_ID_VERIFICATION);
    }
  }

  /**
   * Request reading (or computing) a field. If value cannot be accessed, the process continues.
   *
   * @param key must not be age or place verification - use above methods to request these.
   */
  void addOptionalField(EIDKeys key)
  {
    addField(optionalFields, key);
  }

  /**
   * Request reading (or computing) a field. If value cannot be accessed, the process should abort.
   *
   * @param key must not be age or place verification - use above methods to request these.
   */
  void addRequiredField(EIDKeys key)
  {
    addField(requiredFields, key);
  }

  // end of setters

  private final transient BlackListConnector blackListConnector;

  private Integer requiredAge;

  private boolean verifyDocumentValidity;

  private boolean performRestrictedIdentification;

  private String requiredCommunity;

  private final Set<EIDKeys> requiredFields = new HashSet<>();

  private final Set<EIDKeys> optionalFields = new HashSet<>();

  private final List<TerminalData> cvcChain;

  private final TerminalData cvc;

  private final String sessionID;

  private final String refreshAddress;

  private final String serverAddress;

  private final byte[] masterList;

  private final byte[] defectedList;

  private final List<X509Certificate> masterListCerts;

  private String transactionInfo = null;

  private final String logPrefix;

  private void addField(Set<EIDKeys> keyset, EIDKeys key)
  {
    if (key == EIDKeys.AGE_VERIFICATION || key == EIDKeys.MUNICIPALITY_ID_VERIFICATION)
    {
      throw new IllegalArgumentException("additional input needed - use separate method");
    }
    if (key == EIDKeys.RESTRICTED_ID)
    {
      performRestrictedIdentification = true;
      keyset.add(key);
    }
    else if (key == EIDKeys.DOCUMENT_VALIDITY)
    {
      verifyDocumentValidity = true;
    }
    else
    {
      keyset.add(key);
    }
  }

  @Override
  public List<TerminalData> getCvcChain()
  {
    return cvcChain;
  }

  @Override
  public TerminalData getTerminalCertificate()
  {
    return cvc;
  }

  @Override
  public String getRefreshAddress()
  {
    return refreshAddress;
  }

  @Override
  public String getServerAddress()
  {
    return serverAddress;
  }

  @Override
  public byte[] getMasterList()
  {
    return masterList;
  }

  @Override
  public byte[] getDefectList()
  {
    return defectedList;
  }

  @Override
  public List<X509Certificate> getMasterListCerts()
  {
    return masterListCerts;
  }

  @Override
  public String getLogPrefix()
  {
    return logPrefix;
  }
}

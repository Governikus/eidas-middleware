/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.eidservice;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import de.bund.bsi.eid20.PSCRequestType;
import de.bund.bsi.eid20.SpecificAttributeRequestType;
import de.governikus.eumw.poseidas.cardbase.Hex;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.ATEidAccess.AccessRightEnum;
import de.governikus.eumw.poseidas.cardbase.npa.CVCPermission;
import de.governikus.eumw.poseidas.eidmodel.TerminalData;
import de.governikus.eumw.poseidas.eidmodel.data.EIDKeys;
import de.governikus.eumw.poseidas.eidserver.convenience.CAConnection;
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
   * Return the pre-shared key to be used in the PAOS HTTPs communication. Feel free to change the result type
   * of this method to something more suitable.
   */
  @Override
  public byte[] getPresharedKey()
  {
    return presharedKey.clone();
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

  /**
   * Returns the SHA256ofSAMLRequest as a binary byte array. This will be included inside the object tag
   */
  @Override
  public byte[] getSHA256ofSAMLRequest()
  {
    return sHA256ofSAMLRequest == null ? null : sHA256ofSAMLRequest.clone();
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
                           byte[] presharedKey,
                           String sessionID,
                           byte[] sHA256ofSAMLRequest,
                           BlackListConnector blackListConnector,
                           String refreshAddress,
                           String commErrorAddress,
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
    this.presharedKey = presharedKey.clone();
    this.sessionID = sessionID;
    this.sHA256ofSAMLRequest = sHA256ofSAMLRequest;
    this.blackListConnector = blackListConnector;
    this.refreshAddress = refreshAddress;
    this.commErrorAddress = commErrorAddress;
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
                          byte[] presharedKey,
                          String sessionID,
                          byte[] sHA256ofSAMLRequest,
                          BlackListConnector blackListConnector,
                          String refreshAddress,
                          String commErrorAddress,
                          String serverAddress,
                          byte[] masterList,
                          byte[] defectedList,
                          String transactionInfo,
                          String logPrefix)
  {
    this(cvc, cvcChain, presharedKey, sessionID, sHA256ofSAMLRequest, blackListConnector, refreshAddress,
         commErrorAddress, serverAddress, masterList, null, defectedList, transactionInfo, logPrefix);
  }

  /**
   * Create new instance giving the CVC, pre-shared key and sessionID
   */
  SessionInputImpl(TerminalData cvc,
                          List<TerminalData> cvcChain,
                          byte[] presharedKey,
                          String sessionID,
                          byte[] sHA256ofSAMLRequest,
                          BlackListConnector blackListConnector,
                          String refreshAddress,
                          String commErrorAddress,
                          String serverAddress,
                          List<X509Certificate> masterListCerts,
                          byte[] defectedList,
                          String transactionInfo,
                          String logPrefix)
  {
    this(cvc, cvcChain, presharedKey, sessionID, sHA256ofSAMLRequest, blackListConnector, refreshAddress,
         commErrorAddress, serverAddress, null, masterListCerts, defectedList, transactionInfo, logPrefix);
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
   * request specific attributes
   */
  void setSpecificAttributes(EIDKeys key, boolean required, SpecificAttributeRequestType sart)
  {
    if (required)
    {
      this.requiredFields.add(key);
    }
    else
    {
      this.optionalFields.add(key);
    }
    this.specificAccessAll = sart != null && sart.isAccessAll() != null && sart.isAccessAll();
    this.specificRequests = sart == null ? null : sart.getAttributeRequest();
  }

  /**
   * request a pseudonymous signature of a message
   * 
   * @param message
   */
  void setPSM(byte[] message, boolean required)
  {
    psMessage = message;
    if (required)
    {
      requiredFields.add(EIDKeys.PSM);
    }
    else
    {
      optionalFields.add(EIDKeys.PSM);
    }
  }

  void setPSC(PSCRequestType parameters, boolean required)
  {
    if (parameters.isDocumentType() != null && parameters.isDocumentType())
    {
      this.pscFidList.add(Hex.parse(CVCPermission.AUT_READ_DG01.getFID()));
      this.pscAccessRightSet.add(AccessRightEnum.PSC_DG01);
    }
    if (parameters.isIssuingState() != null && parameters.isIssuingState())
    {
      this.pscFidList.add(Hex.parse(CVCPermission.AUT_READ_DG02.getFID()));
      this.pscAccessRightSet.add(AccessRightEnum.PSC_DG02);
    }
    if (parameters.isDateOfExpiry() != null && parameters.isDateOfExpiry())
    {
      this.pscFidList.add(Hex.parse(CVCPermission.AUT_READ_DG03.getFID()));
      this.pscAccessRightSet.add(AccessRightEnum.PSC_DG03);
    }
    if (parameters.isGivenNames() != null && parameters.isGivenNames())
    {
      this.pscFidList.add(Hex.parse(CVCPermission.AUT_READ_DG04.getFID()));
      this.pscAccessRightSet.add(AccessRightEnum.PSC_DG04);
    }
    if (parameters.isFamilyNames() != null && parameters.isFamilyNames())
    {
      this.pscFidList.add(Hex.parse(CVCPermission.AUT_READ_DG05.getFID()));
      this.pscAccessRightSet.add(AccessRightEnum.PSC_DG05);
    }
    if (parameters.isArtisticName() != null && parameters.isArtisticName())
    {
      this.pscFidList.add(Hex.parse(CVCPermission.AUT_READ_DG06.getFID()));
      this.pscAccessRightSet.add(AccessRightEnum.PSC_DG06);
    }
    if (parameters.isAcademicTitle() != null && parameters.isAcademicTitle())
    {
      this.pscFidList.add(Hex.parse(CVCPermission.AUT_READ_DG07.getFID()));
      this.pscAccessRightSet.add(AccessRightEnum.PSC_DG07);
    }
    if (parameters.isDateOfBirth() != null && parameters.isDateOfBirth())
    {
      this.pscFidList.add(Hex.parse(CVCPermission.AUT_READ_DG08.getFID()));
      this.pscAccessRightSet.add(AccessRightEnum.PSC_DG08);
    }
    if (parameters.isPlaceOfBirth() != null && parameters.isPlaceOfBirth())
    {
      this.pscFidList.add(Hex.parse(CVCPermission.AUT_READ_DG09.getFID()));
      this.pscAccessRightSet.add(AccessRightEnum.PSC_DG09);
    }
    if (parameters.isNationality() != null && parameters.isNationality())
    {
      this.pscFidList.add(Hex.parse(CVCPermission.AUT_READ_DG10.getFID()));
      this.pscAccessRightSet.add(AccessRightEnum.PSC_DG10);
    }
    if (parameters.isSex() != null && parameters.isSex())
    {
      this.pscFidList.add(Hex.parse(CVCPermission.AUT_READ_DG11.getFID()));
      this.pscAccessRightSet.add(AccessRightEnum.PSC_DG11);
    }
    if (parameters.isOptionalDataR() != null && parameters.isOptionalDataR())
    {
      this.pscFidList.add(Hex.parse(CVCPermission.AUT_READ_DG12.getFID()));
      this.pscAccessRightSet.add(AccessRightEnum.PSC_DG12);
    }
    if (parameters.isBirthName() != null && parameters.isBirthName())
    {
      this.pscFidList.add(Hex.parse(CVCPermission.AUT_READ_DG13.getFID()));
      this.pscAccessRightSet.add(AccessRightEnum.PSC_DG13);
    }
    if (parameters.isWrittenSignature() != null && parameters.isWrittenSignature())
    {
      this.pscFidList.add(Hex.parse(CVCPermission.AUT_READ_DG14.getFID()));
      this.pscAccessRightSet.add(AccessRightEnum.PSC_DG14);
    }
    if (parameters.isDateOfIssuance() != null && parameters.isDateOfIssuance())
    {
      this.pscFidList.add(Hex.parse(CVCPermission.AUT_READ_DG15.getFID()));
      this.pscAccessRightSet.add(AccessRightEnum.PSC_DG15);
    }
    if (parameters.isPlaceOfResidence() != null && parameters.isPlaceOfResidence())
    {
      this.pscFidList.add(Hex.parse(CVCPermission.AUT_READ_DG17.getFID()));
      this.pscAccessRightSet.add(AccessRightEnum.PSC_DG17);
    }
    if (parameters.isMunicipalityID() != null && parameters.isMunicipalityID())
    {
      this.pscFidList.add(Hex.parse(CVCPermission.AUT_READ_DG18.getFID()));
      this.pscAccessRightSet.add(AccessRightEnum.PSC_DG18);
    }
    if (parameters.isResidencePermitI() != null && parameters.isResidencePermitI())
    {
      this.pscFidList.add(Hex.parse(CVCPermission.AUT_READ_DG19.getFID()));
      this.pscAccessRightSet.add(AccessRightEnum.PSC_DG19);
    }
    if (parameters.isResidencePermitII() != null && parameters.isResidencePermitII())
    {
      this.pscFidList.add(Hex.parse(CVCPermission.AUT_READ_DG20.getFID()));
      this.pscAccessRightSet.add(AccessRightEnum.PSC_DG20);
    }
    if (parameters.isPhoneNumber() != null && parameters.isPhoneNumber())
    {
      this.pscFidList.add(Hex.parse(CVCPermission.AUT_READ_DG21.getFID()));
      this.pscAccessRightSet.add(AccessRightEnum.PSC_DG21);
    }
    if (parameters.isEmailAddress() != null && parameters.isEmailAddress())
    {
      this.pscFidList.add(Hex.parse(CVCPermission.AUT_READ_DG22.getFID()));
      this.pscAccessRightSet.add(AccessRightEnum.PSC_DG22);
    }
    if (parameters.isSpecificAttribute() != null && parameters.isSpecificAttribute())
    {
      this.pscIncludeSpecific = true;
    }
    if (required)
    {
      requiredFields.add(EIDKeys.PSC);
    }
    else
    {
      optionalFields.add(EIDKeys.PSC);
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

  private final byte[] sHA256ofSAMLRequest;

  private final Set<EIDKeys> requiredFields = new HashSet<>();

  private final Set<EIDKeys> optionalFields = new HashSet<>();

  private final List<TerminalData> cvcChain;

  private final TerminalData cvc;

  private final byte[] presharedKey;

  private final String sessionID;

  private final String refreshAddress;

  private final String commErrorAddress;

  private final String serverAddress;

  private final byte[] masterList;

  private final byte[] defectedList;

  private final List<X509Certificate> masterListCerts;

  private String transactionInfo = null;

  private final String logPrefix;

  private CAConnection caConnection;

  private byte[] psMessage;

  private final List<byte[]> pscFidList = new ArrayList<>();

  private final Set<AccessRightEnum> pscAccessRightSet = new HashSet<>();

  private boolean pscIncludeSpecific = false;

  private boolean specificAccessAll = false;

  private byte[] specificRequests = null;

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
  public String getCommunicationErrorAddress()
  {
    return commErrorAddress;
  }

  @Override
  public String getLogPrefix()
  {
    return logPrefix;
  }

  @Override
  public CAConnection getCAConnection()
  {
    return this.caConnection;
  }

  public void setCAConnection(CAConnection connection)
  {
    this.caConnection = connection;
  }

  @Override
  public byte[] getPsMessage()
  {
    return this.psMessage;
  }

  @Override
  public List<byte[]> getPscFidList()
  {
    return this.pscFidList;
  }

  @Override
  public Set<AccessRightEnum> getPscAccessRightSet()
  {
    return this.pscAccessRightSet;
  }

  @Override
  public boolean isPscIncludeSpecific()
  {
    return this.pscIncludeSpecific;
  }

  @Override
  public boolean isAccessAllSpecificAttributes()
  {
    return this.specificAccessAll;
  }

  @Override
  public byte[] getSpecificRequests()
  {
    return this.specificRequests;
  }
}

/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
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
import lombok.AccessLevel;
import lombok.Getter;
import lombok.RequiredArgsConstructor;


/**
 * Wrapper for all information needed to build the eCard API dialog. The getters should reveal all information
 * required to build the EACSessionInputType object which is needed by the eCard API (see BSI TR-03112-7 page
 * 39). This is part of the eCardAPIs interface but AF does not want an interface which can be used without
 * defining extra classes.
 *
 * @author tt
 */
@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
@Getter
public class SessionInputImpl implements SessionInput
{

  private static final long serialVersionUID = 1L;

  private final transient BlackListConnector blackListConnector;

  private Integer requiredAge;

  private boolean verifyDocumentValidity;

  private boolean performRestrictedIdentification;

  private String requiredCommunity;

  private final Set<EIDKeys> requiredFields = new HashSet<>();

  private final Set<EIDKeys> optionalFields = new HashSet<>();

  private final List<TerminalData> cvcChain;

  private final TerminalData terminalCertificate;

  private final String sessionID;

  private final byte[] masterList;

  private final byte[] defectList;

  private final List<X509Certificate> masterListCerts;

  private final String transactionInfo;

  private final String logPrefix;

  /**
   * Create new instance giving the CVC, pre-shared key and sessionID
   */
  SessionInputImpl(TerminalData cvc,
                   List<TerminalData> cvcChain,
                   String sessionID,
                   BlackListConnector blackListConnector,
                   byte[] masterList,
                   byte[] defectList,
                   String transactionInfo,
                   String logPrefix)
  {
    this(blackListConnector, cvcChain, cvc, sessionID, masterList, defectList, null, transactionInfo, logPrefix);
  }

  /**
   * Create new instance giving the CVC, pre-shared key and sessionID
   */
  SessionInputImpl(TerminalData cvc,
                   List<TerminalData> cvcChain,
                   String sessionID,
                   BlackListConnector blackListConnector,
                   List<X509Certificate> masterListCerts,
                   byte[] defectList,
                   String transactionInfo,
                   String logPrefix)
  {
    this(blackListConnector, cvcChain, cvc, sessionID, null, defectList, masterListCerts, transactionInfo, logPrefix);
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
}

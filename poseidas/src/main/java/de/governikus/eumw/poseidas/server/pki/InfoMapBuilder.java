/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.pki;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

import jakarta.xml.bind.DatatypeConverter;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import de.governikus.eumw.poseidas.cardbase.asn1.ASN1;
import de.governikus.eumw.poseidas.cardbase.asn1.OID;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.CertificateDescription;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.CertificateDescriptionPath;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.CertificateHolderAuthorizationTemplate;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.ECCVCPath;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.ECCVCertificate;
import de.governikus.eumw.poseidas.cardbase.crypto.DigestUtil;
import de.governikus.eumw.poseidas.cardbase.npa.CVCPermission;
import de.governikus.eumw.poseidas.eidmodel.TerminalData;
import de.governikus.eumw.poseidas.gov2server.constants.admin.AdminPoseidasConstants;
import de.governikus.eumw.poseidas.gov2server.constants.admin.IDManagementCodes;
import de.governikus.eumw.poseidas.gov2server.constants.admin.ManagementMessage;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;


/**
 * Crates a Map with some interesting attributes out of a given CVC
 *
 * @author tautenhahn, hme
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class InfoMapBuilder
{

  private static final Log LOG = LogFactory.getLog(InfoMapBuilder.class);

  /**
   * Return a map containing the most interesting attributes from given terminalPermission as parsed objects.
   *
   * @param facade
   * @param cvcRefID Reference ID for the provider
   * @param withBlkNumber include the number of entries in the blacklist, this could take some more time.
   */
  static Map<String, Object> createInfoMap(TerminalPermissionAO facade,
                                           String cvcRefID,
                                           boolean withBlkNumber)
  {
    if (facade == null)
    {
      return null;
    }

    Map<String, Object> result = new HashMap<>();
    result.put(AdminPoseidasConstants.VALUE_PERMISSION_DATA_ERROR_MESSAGE, new HashSet<ManagementMessage>());
    result.put(AdminPoseidasConstants.VALUE_IS_PUBLIC_CLIENT, facade.isPublicClient(cvcRefID));

    TerminalPermission terminal = facade.getTerminalPermission(cvcRefID);
    if (terminal == null)
    {
      return result;
    }


    result.put(AdminPoseidasConstants.VALUE_PERMISSION_DATA_BLACK_LIST_DATE,
               terminal.getBlackListStoreDate());
    result.put(AdminPoseidasConstants.VALUE_PERMISSION_DATA_MASTER_LIST_DATE,
               terminal.getMasterListStoreDate());
    result.put(AdminPoseidasConstants.VALUE_PERMISSION_DATA_DEFECT_LIST_DATE,
               terminal.getDefectListStoreDate());

    if (terminal.getPendingRequest() != null)
    {
      result.put(AdminPoseidasConstants.VALUE_PERMISSION_DATA_PENDING_CERT_REQUEST,
                 DatatypeConverter.printBase64Binary(terminal.getPendingRequest().getRequestData()));
      result.put(AdminPoseidasConstants.VALUE_PERMISSION_DATA_PENDING_CERT_REQUEST_DATE,
                 terminal.getPendingRequest().getLastChanged());
      result.put(AdminPoseidasConstants.VALUE_PERMISSION_DATA_PENDING_CERT_REQUEST_STATUS,
                 terminal.getPendingRequest().getStatus().toString());
      result.put(AdminPoseidasConstants.VALUE_PERMISSION_DATA_PENDING_CERT_REQUEST_MESSAGE_ID,
                 terminal.getPendingRequest().getMessageID());
    }

    if (terminal.getCvcDescription() != null)
    {
      getInfoFromCvcDescription(result, terminal.getCvcDescription(), terminal.getRefID());
    }
    if (terminal.getCvc() != null)
    {
      try
      {
        TerminalData cvc = new TerminalData(terminal.getCvc());
        getInfoFromCvc(result, cvc, terminal.getRefID(), terminal.getSectorID());
        // TODO: The number of BlackListEntries is never shown anywhere but this query can be expensive
        if (cvc.getSectorPublicKeyHash() != null && withBlkNumber)
        {
          result.put(AdminPoseidasConstants.VALUE_PERMISSION_DATA_BLACKLIST_ENTRIES,
                     facade.getNumberBlacklistEntries(cvc.getSectorPublicKeyHash()));
        }
      }
      catch (IOException e)
      {
        throw new IllegalArgumentException("unable to parse given cvc", e);
      }
    }


    @SuppressWarnings("unchecked")
    Collection<ManagementMessage> errorMessages = (Collection<ManagementMessage>)result.get(AdminPoseidasConstants.VALUE_PERMISSION_DATA_ERROR_MESSAGE);
    if (!errorMessages.isEmpty() || terminal.getCvc() == null || terminal.getCvcDescription() == null)
    {
      // If the cvc or the cvc description already have error we do not want to check if they are matching.
      return result;
    }

    try
    {
      new TerminalData(terminal.getCvc(), terminal.getCvcDescription(), terminal.getCvcPrivateKey(),
                       terminal.getRiKey1(), terminal.getPsKey());
    }
    catch (Exception e)
    {
      if (LOG.isInfoEnabled())
      {
        LOG.info(cvcRefID + ": CVC description and CVC do not match", e);
      }
      addErrorMessage(result, IDManagementCodes.CVC_DESCRIPTION_NOT_MATCH.createMessage(terminal.getRefID()));
      return result;
    }
    checkTerminalPermission(result, terminal);
    return result;
  }

  private static void addErrorMessage(Map<String, Object> result, ManagementMessage message)
  {
    @SuppressWarnings("unchecked")
    Collection<ManagementMessage> errorMessages = (Collection<ManagementMessage>)result.get(AdminPoseidasConstants.VALUE_PERMISSION_DATA_ERROR_MESSAGE);
    errorMessages.add(message);
  }

  private static void checkTerminalPermission(Map<String, Object> result, TerminalPermission terminal)
  {
    if (terminal.getMasterList() == null)
    {
      addErrorMessage(result,
                      IDManagementCodes.NO_LIST_AVAILABLE.createMessage(terminal.getRefID(),
                                                                        "ID.jsp.nPaConfiguration.masterList"));
    }
    if (terminal.getDefectList() == null)
    {
      addErrorMessage(result,
                      IDManagementCodes.NO_LIST_AVAILABLE.createMessage(terminal.getRefID(),
                                                                        "ID.jsp.nPaConfiguration.defectList"));
    }
    if (terminal.getSectorID() == null)
    {
      addErrorMessage(result,
                      IDManagementCodes.NO_LIST_AVAILABLE.createMessage(terminal.getRefID(),
                                                                        "ID.jsp.nPaConfiguration.blackList"));
    }
    if (terminal.getRiKey1() == null)
    {
      addErrorMessage(result,
                      IDManagementCodes.NO_LIST_AVAILABLE.createMessage(terminal.getRefID(),
                                                                        "ID.jsp.nPaConfiguration.riKey1"));
    }
  }

  private static void getInfoFromCvc(Map<String, Object> result,
                                     TerminalData cvc,
                                     String cvcRefID,
                                     byte[] sectorID)
  {
    try
    {
      if (cvc.getCHAT() != null)
      {
        List<String> allowedList = getAllowedList(cvc.getCHAT());
        result.put(AdminPoseidasConstants.VALUE_PERMISSION_DATA_ALLOWED_DATA_FIELDS, allowedList);
      }
      result.put(AdminPoseidasConstants.VALUE_PERMISSION_DATA_EXPIRATION_DATE, cvc.getExpirationDate());
      result.put(AdminPoseidasConstants.VALUE_PERMISSION_DATA_EFFECTIVE_DATE, cvc.getEffectiveDate());
      result.put(AdminPoseidasConstants.VALUE_PERMISSION_DATA_HOLDERREFERENCE,
                 cvc.getHolderReferenceString());
      result.put(AdminPoseidasConstants.VALUE_PERMISSION_DATA_CA_REFERENCE, cvc.getCAReferenceString());
      result.put(AdminPoseidasConstants.VALUE_PERMISSION_DATA_SECTOR_PUBLIC_KEY_HASH,
                 DatatypeConverter.printHexBinary(cvc.getSectorPublicKeyHash()));
      if (sectorID != null
          && (cvc.getSectorPublicKeyHash() == null || !Arrays.equals(cvc.getSectorPublicKeyHash(), sectorID)))
      {
        addErrorMessage(result, IDManagementCodes.SECTOR_HASH_DOES_NOT_MATCH.createMessage(cvcRefID));
      }
    }
    catch (Exception e)
    {
      if (LOG.isErrorEnabled())
      {
        LOG.error(cvcRefID + ": can not parse CVC", e);
      }
      addErrorMessage(result, IDManagementCodes.INCOMPLETE_TERMINAL_CERTIFICATE.createMessage(cvcRefID));
    }
    try
    {
      ECCVCertificate rootCert = new ECCVCertificate(cvc.getEncoded());
      OID oid = new OID(rootCert.getChildElementByPath(ECCVCPath.PUBLIC_KEY_OID).getEncoded());
      MessageDigest md = DigestUtil.getDigestByOID(oid);
      result.put(AdminPoseidasConstants.VALUE_PERMISSION_DATA_MESSAGE_DIGEST, md);
    }
    catch (Exception e)
    {
      if (LOG.isErrorEnabled())
      {
        LOG.error(cvcRefID + ": can not calculate the certificate description digest", e);
      }
      addErrorMessage(result, IDManagementCodes.INCOMPLETE_TERMINAL_CERTIFICATE.createMessage(cvcRefID));
    }
  }

  private static void getInfoFromCvcDescription(Map<String, Object> result,
                                                byte[] cvcDescBytes,
                                                String cvcRefID)
  {
    try
    {
      CertificateDescription desc = new CertificateDescription(cvcDescBytes);
      putIfNotNull(result,
                   AdminPoseidasConstants.VALUE_PERMISSION_DATA_TERMS_OF_USAGE_HTML,
                   desc.getTermsOfUsageHTML());
      putIfNotNull(result,
                   AdminPoseidasConstants.VALUE_PERMISSION_DATA_TERMS_OF_USAGE_PLAIN_TEXT,
                   desc.getTermsOfUsagePlainText());
      putIfNotNull(result, AdminPoseidasConstants.VALUE_PERMISSION_DATA_ISSUER_NAME, desc.getIssuerName());
      putIfNotNull(result, AdminPoseidasConstants.VALUE_PERMISSION_DATA_ISSUER_URL, desc.getIssuerUrl());
      putIfNotNull(result, AdminPoseidasConstants.VALUE_PERMISSION_DATA_SUBJECT_NAME, desc.getSubjectName());
      putIfNotNull(result, AdminPoseidasConstants.VALUE_PERMISSION_DATA_SUBJECT_URL, desc.getSubjectUrl());

      ASN1 redirectURLAsn1 = desc.getCertificateDescriptionPart(CertificateDescriptionPath.REDIRECT_URL);

      if (redirectURLAsn1 != null && redirectURLAsn1.getValue() != null)
      {
        result.put(AdminPoseidasConstants.VALUE_PERMISSION_DATA_REDIRECT_URL,
                   new String(redirectURLAsn1.getValue(), StandardCharsets.UTF_8));
      }

      ASN1 certHashes = desc.getCertificateDescriptionPart(CertificateDescriptionPath.COMM_CERTIFICATES);
      if (certHashes != null)
      {
        List<String> commCertHashList = new ArrayList<>();
        for ( ASN1 hashes : certHashes.getChildElementList() )
        {
          String hash = DatatypeConverter.printHexBinary(hashes.getValue());
          commCertHashList.add(hash);
        }
        result.put(AdminPoseidasConstants.VALUE_PERMISSION_DATA_COMMUNICATION_CERTS_HASHES, commCertHashList);
      }
    }
    catch (IOException e)
    {
      if (LOG.isErrorEnabled())
      {
        LOG.error(cvcRefID + ": Can not parse CVC description", e);
      }
      addErrorMessage(result, IDManagementCodes.INCOMPLETE_TERMINAL_CERTIFICATE.createMessage(cvcRefID));
    }
  }

  private static List<String> getAllowedList(CertificateHolderAuthorizationTemplate chat)
  {
    List<String> allowedList = new ArrayList<>();
    for ( CVCPermission option : chat.getAllRights() )
    {
      String name = option.getDataFieldName();
      if (!allowedList.contains(name))
      {
        allowedList.add(name);
      }
    }
    return allowedList;
  }

  private static void putIfNotNull(Map<String, Object> result, String key, Object value)
  {
    if (value != null)
    {
      result.put(key, value);
    }
  }
}

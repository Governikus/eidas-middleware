/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.pki;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import de.governikus.autent.asn1.CVC;
import de.governikus.autent.asn1.CVCBody;
import de.governikus.autent.asn1.CVCDescription;
import de.governikus.eumw.poseidas.eidmodel.TerminalData;
import de.governikus.eumw.poseidas.gov2server.constants.admin.AdminPoseidasConstants;
import de.governikus.eumw.poseidas.gov2server.constants.admin.IDManagementCodes;
import de.governikus.eumw.poseidas.gov2server.constants.admin.ManagementMessage;
import de.governikus.eumw.poseidas.server.pki.blocklist.BlockListService;
import de.governikus.eumw.poseidas.server.pki.entities.TerminalPermission;
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
   */
  static Map<String, Object> createInfoMap(TerminalPermissionAO facade,
                                           BlockListService blockListService,
                                           String cvcRefID)
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

    if (terminal.getCvcDescription() != null)
    {
      getInfoFromCvcDescription(result, terminal.getCvcDescription());
    }
    if (terminal.getCvc() != null)
    {
      try
      {
        getInfoFromCvc(result, new CVC(terminal.getCvc()), terminal.getRefID(), terminal.getSectorID());
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

  private static void getInfoFromCvc(Map<String, Object> result, CVC cvc, String cvcRefID, byte[] sectorID)
  {
    try
    {
      CVCBody cvcBody = cvc.getBody();
      result.put(AdminPoseidasConstants.VALUE_PERMISSION_DATA_EXPIRATION_DATE,
                 cvcBody.getCertificateExpirationDate().getDate());
      result.put(AdminPoseidasConstants.VALUE_PERMISSION_DATA_EFFECTIVE_DATE,
                 cvcBody.getCertificateEffectiveDate().getDate());
      result.put(AdminPoseidasConstants.VALUE_PERMISSION_DATA_HOLDERREFERENCE, cvcBody.getCertificateHolderReference());
      result.put(AdminPoseidasConstants.VALUE_PERMISSION_DATA_CA_REFERENCE,
                 cvcBody.getCertificationAuthorityReference());
      byte[] firstSectorPublicKeyHash = cvcBody.getCertificateExtensions().getFirstSectorPublicKeyHash();
      if (sectorID != null && (firstSectorPublicKeyHash == null || !Arrays.equals(firstSectorPublicKeyHash, sectorID)))
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
  }

  private static void getInfoFromCvcDescription(Map<String, Object> result, byte[] cvcDescBytes)
  {
    CVCDescription desc = new CVCDescription(cvcDescBytes);
    putIfNotNull(result,
                 AdminPoseidasConstants.VALUE_PERMISSION_DATA_TERMS_OF_USAGE_PLAIN_TEXT,
                 desc.getTermsOfUsage());
    putIfNotNull(result, AdminPoseidasConstants.VALUE_PERMISSION_DATA_ISSUER_NAME, desc.getIssuerName());
    putIfNotNull(result, AdminPoseidasConstants.VALUE_PERMISSION_DATA_ISSUER_URL, desc.getIssuerUrl());
    putIfNotNull(result, AdminPoseidasConstants.VALUE_PERMISSION_DATA_SUBJECT_NAME, desc.getSubjectName());
    putIfNotNull(result, AdminPoseidasConstants.VALUE_PERMISSION_DATA_SUBJECT_URL, desc.getSubjectUrl());
  }

  private static void putIfNotNull(Map<String, Object> result, String key, Object value)
  {
    if (value != null)
    {
      result.put(key, value);
    }
  }
}

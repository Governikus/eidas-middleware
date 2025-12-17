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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import de.governikus.eumw.poseidas.cardbase.asn1.npa.CertificateDescription;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.ECCVCertificate;
import de.governikus.eumw.poseidas.eidmodel.TerminalData;
import de.governikus.eumw.poseidas.eidserver.model.signeddata.BlackList;
import de.governikus.eumw.poseidas.eidserver.model.signeddata.DefectList;
import de.governikus.eumw.poseidas.eidserver.model.signeddata.MasterList;
import de.governikus.eumw.poseidas.gov2server.GovManagementException;
import de.governikus.eumw.poseidas.gov2server.constants.admin.IDManagementCodes;


/**
 * Helper class to perform plausibility checks for imported CVC-related data
 *
 * @author tautenhahn
 */
public class InputDataCVCChecker
{

  private static final Log LOG = LogFactory.getLog(InputDataCVCChecker.class);

  /**
   * Perform various consistency checks on given data.
   *
   * @param cvc serialized CVC
   * @param cvcDescription ASN1 encoded description
   * @param cvcPrivateKey
   * @param riKey1
   * @param psKey
   * @param chain
   * @param masterList
   * @param defectList
   * @param blackList
   * @throws GovManagementException in case an inconsistency has been detected
   */
  public void checkInputData(byte[] cvc,
                             byte[] cvcDescription,
                             byte[] cvcPrivateKey,
                             byte[] riKey1,
                             byte[] psKey,
                             byte[][] chain,
                             byte[] masterList,
                             byte[] defectList,
                             byte[] blackList)
    throws GovManagementException
  {
    assertNotEmpty(cvc, "ID.jsp.nPaConfiguration.cvc");
    assertNotEmpty(cvcDescription, "ID.jsp.nPaConfiguration.cvcDescription");
    assertNotEmpty(riKey1, "ID.jsp.nPaConfiguration.riKey1");
    assertNotEmpty(masterList, "ID.jsp.nPaConfiguration.masterList");
    assertNotEmpty(defectList, "ID.jsp.nPaConfiguration.defectList");
    assertNotEmpty(blackList, "ID.jsp.nPaConfiguration.blackList");
    if (chain == null || chain.length == 0)
    {
      throw new GovManagementException(IDManagementCodes.MISSING_INPUT_VALUE, "ID.jsp.nPaConfiguration.chain");
    }
    assertNotEmpty(chain[0], "ID.jsp.nPaConfiguration.chain");
    checkCVCAndDescription(cvc, cvcDescription, cvcPrivateKey, riKey1, psKey);
    checkMasterList(masterList);
    checkDefectList(defectList);
    try
    {
      checkBlackList(blackList, new ECCVCertificate(cvc).getSectorPublicKeyHash());
    }
    catch (IOException e)
    {
      throw new IllegalArgumentException("unable to parse given cvc", e);
    }
  }

  /**
   * Check if given value either can be parsed as master list or looks like some other data type. Importing master lists
   * in different formats is supported.
   *
   * @param masterList
   * @throws GovManagementException
   */
  public void checkMasterList(byte[] masterList) throws GovManagementException
  {
    try
    {
      if (masterList.length < 2 || !(masterList[0] == 0x50 && masterList[1] == 0X4b))
      {
        new MasterList(masterList);
      }
    }
    catch (Exception e)
    {
      throw invalidInput("masterList", e, false);
    }
  }

  /**
   * Make sure given value can be parsed as defect list
   *
   * @param defectList
   * @throws GovManagementException
   */
  public void checkDefectList(byte[] defectList) throws GovManagementException
  {
    try
    {
      new DefectList(defectList);
    }
    catch (Exception e)
    {
      throw invalidInput("defectList", e, false);
    }
  }

  public void checkCvcDescription(byte[] cvcDescription) throws GovManagementException
  {
    try
    {
      new CertificateDescription(cvcDescription);
    }
    catch (Exception e)
    {
      throw invalidInput("cvcDescription", e, false);
    }
  }

  private void checkCVCAndDescription(byte[] cvc,
                                      byte[] cvcDescription,
                                      byte[] cvcPrivateKey,
                                      byte[] riKey1,
                                      byte[] psKey)
    throws GovManagementException
  {
    TerminalData parsed = null;
    try
    {
      parsed = new TerminalData(cvc, cvcDescription, cvcPrivateKey, riKey1, psKey);
    }
    catch (IllegalArgumentException e)
    {
      Throwable t = e.getCause();

      if (t != null && t.getStackTrace()[3].getClassName().endsWith("CVCDescription"))
      {
        throw invalidInput("cvcDescription", t, false);
      }
      throw invalidInput("cvc", t, false);
    }
    catch (NullPointerException e) // NOPMD NPE is thrown by CVC class
    {
      if (e.getStackTrace()[0].getClassName().endsWith("CVCWrapper"))
      {
        throw invalidInput("cvc", e, false);
      }
      throw invalidInput("cvc", e, true);
    }
    catch (Exception e)
    {
      throw invalidInput("cvc", e, true);
    }
    if (parsed.getCVCDescription() == null || stringMissing(parsed.getCVCDescription().getSubjectName()))
    {
      throw invalidInput("cvcDescription", null, false);
    }
  }

  private void assertNotEmpty(byte[] input, String fieldName) throws GovManagementException
  {
    if (input == null || input.length == 0)
    {
      throw new GovManagementException(IDManagementCodes.MISSING_INPUT_VALUE, fieldName);
    }
  }

  private boolean stringMissing(String input)
  {
    return input == null || input.trim().isEmpty();
  }

  /**
   * parse black list and check sector ID
   *
   * @param input
   * @param sectorIdCvc
   * @throws GovManagementException
   */
  public void checkBlackList(byte[] input, byte[] sectorIdCvc) throws GovManagementException
  {
    try
    {
      BlackList blackList = new BlackList(input);
      if (!blackList.getBlacklistDetails().isEmpty())
      {
        byte[] sectorIdBlacklist = blackList.getBlacklistDetails().get(0).getSectorID();
        if (sectorIdCvc != null && (sectorIdBlacklist == null || !Arrays.equals(sectorIdBlacklist, sectorIdCvc)))
        {
          throw new GovManagementException(IDManagementCodes.INVALID_INPUT_DATA,
                                           "sectorID from blacklist and CVC do not match");
        }
      }
    }
    catch (GovManagementException e)
    {
      throw e;
    }
    catch (Exception e)
    {
      throw invalidInput("blackList", e, false);
    }
  }

  private GovManagementException invalidInput(String name, Throwable t, boolean isInternalError)
  {
    if (isInternalError)
    {
      LOG.error("unspecified problem parsing input data", t);
    }
    return new GovManagementException(IDManagementCodes.INVALID_INPUT_DATA, "ID.jsp.nPaConfiguration." + name);
  }
}

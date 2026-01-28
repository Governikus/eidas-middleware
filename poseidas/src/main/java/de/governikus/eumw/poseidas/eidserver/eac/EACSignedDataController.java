/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.eidserver.eac;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.IssuerAndSerialNumber;
import org.bouncycastle.asn1.pkcs.SignedData;
import org.bouncycastle.asn1.pkcs.SignerInfo;

import de.governikus.eumw.poseidas.ecardcore.model.ResultMajor;
import de.governikus.eumw.poseidas.ecardcore.model.ResultMinor;
import de.governikus.eumw.poseidas.ecardcore.utilities.ECardCoreUtil;
import de.governikus.eumw.poseidas.eidserver.model.signeddata.Defect;
import de.governikus.eumw.poseidas.eidserver.model.signeddata.DefectKnown;
import de.governikus.eumw.poseidas.eidserver.model.signeddata.DefectKnown.DefectType;
import de.governikus.eumw.poseidas.eidserver.model.signeddata.DefectKnownParameter;
import de.governikus.eumw.poseidas.eidserver.model.signeddata.DefectList;
import lombok.Getter;
import oasis.names.tc.dss._1_0.core.schema.ObjectFactory;
import oasis.names.tc.dss._1_0.core.schema.Result;


/**
 * EACSignedDataController for providing defect list handling
 *
 * @author Ole Behrens
 */
public class EACSignedDataController extends EACSignedDataParser
{

  private final byte[] data;

  private List<Defect> cardDefects;

  private final ObjectFactory factory;

  @Getter
  private IssuerAndSerialNumber issuerAndSerialNumber;

  /**
   * Create a controller with card data and server defect list.<br/>
   * Object used to handle defect list behavior for a card in sequence
   *
   * @param data from card
   * @param list from server representing defects
   * @throws IOException if data cannot be used with list
   */
  public EACSignedDataController(byte[] data, DefectList list, String logPrefix) throws IOException
  {
    super(logPrefix);
    if (data == null || data.length < 1)
    {
      throw new IOException("No signed data available for controll");
    }
    this.data = data.clone();

    if (list == null)
    {
      throw new IOException("No defect list available for controll");
    }
    identifyCard(list);
    factory = new ObjectFactory();
  }

  /**
   * Indicates if the card is mentioned on a defect list or by a defect
   *
   * @return true if card is defected
   */
  public boolean containDefects()
  {
    return !cardDefects.isEmpty();
  }

  /**
   * Indicates if the card has defects of type {@link DefectType}
   *
   * @param type to be checked
   * @return true if card contains this defect type
   */
  public boolean isCardAffectedBy(DefectKnown.DefectType type)
  {
    return !getDefectsWithType(type).isEmpty();
  }

  /**
   * Get all defects of {@link DefectType} for the card
   *
   * @param type to be defects should be returned
   * @return list of identified defects
   */
  private List<Defect> getDefectsWithType(DefectKnown.DefectType type)
  {
    List<Defect> defectsWithType = new ArrayList<>();
    for ( Defect defect : cardDefects )
    {
      if (defect.containsKnownDefectsOfType(type))
      {
        defectsWithType.add(defect);
      }
    }
    return defectsWithType;
  }

  /**
   * Returns a result representing the
   *
   * @param type
   * @return
   */
  public Result getDefectResult(DefectKnown.DefectType type)
  {
    // Get defects found
    List<Defect> defects = getDefectsWithType(type);
    // Create the result to be returned
    Result result = factory.createResult();
    result.setResultMajor(ResultMajor.OK.toString());

    if (!defects.isEmpty())
    {
      switch (type)
      {
        case ID_CERT_REVOKED:
          StringBuilder resultMessage = new StringBuilder("Card blocked by defect: ");
          resultMessage.append(type.toString());
          for ( Defect defect : defects )
          {
            for ( DefectKnown knownDefect : defect.getKnownDefectsOfType(type) )
            {
              Object obj = knownDefect.getParameter().getParameterObject();
              DefectKnownParameter.StatusCode status = (DefectKnownParameter.StatusCode)obj;
              resultMessage.append("\n" + status);
            }
          }
          result.setResultMajor(ResultMajor.ERROR.toString());
          result.setResultMinor(ResultMinor.COMMON_INTERNAL_ERROR.toString());
          result.setResultMessage(ECardCoreUtil.generateInternationalStringType(resultMessage.toString()));
          break;

        case ID_EID_INTEGRITY:
          result.setResultMajor(ResultMajor.ERROR.toString());
          result.setResultMinor(ResultMinor.COMMON_INTERNAL_ERROR.toString());
          result.setResultMessage(ECardCoreUtil.generateInternationalStringType("Card data blocked by defect: \n"
                                                                                + type.toStringDetail()));
          break;

        default:
          result.setResultMajor(ResultMajor.ERROR.toString());
          result.setResultMinor(ResultMinor.SAL_SECURITY_CONDITION_NOT_SATISFIED.toString());
          result.setResultMessage(ECardCoreUtil.generateInternationalStringType("Card affected by defect: \n"
                                                                                + type.toStringDetail()));
          break;
      }
    }
    return result;
  }

  /**
   * Get a list of affected data groups for this card that are malformed
   *
   * @return list of data groups identifier
   */
  public List<Integer> getDataGroupsMalformed()
  {
    return getDefectDataGroups(DefectType.ID_EID_DG_MALFORMED);
  }

  public X509Certificate getReplacedCertificate()
  {
    if (isCardAffectedBy(DefectType.ID_CERT_REPLACED))
    {
      List<Defect> cardDefect = getDefectsWithType(DefectType.ID_CERT_REPLACED);
      if (cardDefect.isEmpty())
      {
        LOG.debug("Card has no cert replaced defect");
        return null;
      }
      Defect defect = cardDefect.get(0);
      List<DefectKnown> certReplaceElements = defect.getKnownDefectsOfType(DefectType.ID_CERT_REPLACED);
      if (certReplaceElements.isEmpty())
      {
        LOG.debug("No replaced certificate element found");
      }
      DefectKnown defectKnown = certReplaceElements.get(0);
      return defectKnown.getParameter().getReplacedCertificate();
    }
    return null;
  }

  /**
   * Get the data groups for specific type. Note: Must return an int[] from DefectKnownParameter
   *
   * @param type to be found
   * @return list of identifier
   */
  private List<Integer> getDefectDataGroups(DefectType type)
  {
    List<Integer> dataGroups = new ArrayList<>();
    if (isCardAffectedBy(type))
    {
      List<Defect> defectsWithType = getDefectsWithType(type);
      for ( Defect defect : defectsWithType )
      {
        List<DefectKnown> knownDefects = defect.getKnownDefectsOfType(type);
        for ( DefectKnown known : knownDefects )
        {
          DefectKnownParameter parameter = known.getParameter();
          int[] parameterObject = (int[])parameter.getParameterObject();
          for ( int dataGroup : parameterObject )
          {
            dataGroups.add(dataGroup);
          }
        }
      }
    }
    return dataGroups;
  }

  /**
   * If data is available try to find the card on list
   *
   * @param list to be searched for card
   * @throws IOException
   */
  private void identifyCard(DefectList list) throws IOException
  {
    cardDefects = new ArrayList<>();
    // Get the root data object
    SignedData signedData = getSignedData(data);
    // Get signature informations
    @SuppressWarnings("unchecked")
    Enumeration<ASN1Sequence> signatureInfosFromCard = signedData.getSignerInfos().getObjects();
    if (!signatureInfosFromCard.hasMoreElements())
    {
      throw new IOException("Received card data incorrect");
    }

    int shouldBeOne = 0;
    do
    {
      shouldBeOne++;
      SignerInfo signatureInfo = new SignerInfo(signatureInfosFromCard.nextElement());
      issuerAndSerialNumber = signatureInfo.getIssuerAndSerialNumber();

      if (shouldBeOne == 2 && LOG.isInfoEnabled())
      {
        LOG.info(logPrefix + "Found multiple card identifier");
      }
      if (LOG.isDebugEnabled())
      {
        LOG.debug(logPrefix + "Check issuer and serial for card: " + issuerAndSerialNumber.toString());
      }
      if (list.containDefectsForCard(issuerAndSerialNumber))
      {
        cardDefects.addAll(list.getDefects(issuerAndSerialNumber));
      }
    }
    while (signatureInfosFromCard.hasMoreElements());
  }
}

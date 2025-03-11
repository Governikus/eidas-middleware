/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardbase.npa;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import de.governikus.eumw.poseidas.cardbase.ArrayUtil;
import de.governikus.eumw.poseidas.cardbase.ByteUtil;
import de.governikus.eumw.poseidas.cardbase.asn1.ASN1;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.SecurityInfos;


/**
 * Utility class used in nPA context. (Separated from NPAUtil in client as this is also required on server
 * side.)
 *
 * @author Arne Stahlbock, ast@bos-bremen.de
 */
public class NPAUtil
{

  public static final String FID_EFPRKD = "fidEF.PrKD";

  public static final String FID_EFCD = "fidEF.CD";

  private static final String FID_EFAOD = "fidEF.AOD";

  public static final String FID_CACERT = "fidCACert";

  public static final String FID_CERT = "fidCert";

  public static final String PRK_ID = "PrKID";

  private static final String PIN_ID = "PinID";

  /**
   * Constructor.
   */
  private NPAUtil()
  {
    super();
  }

  /**
   * Extracts {@link SecurityInfos} from EF.CardSecurity.
   *
   * @param cardSecurityBytes complete content of EF.CardSecurity, <code>null</code> or empty not permitted
   * @return {@link SecurityInfos}
   * @throws IOException if extracting / decoding fails
   */
  public static SecurityInfos fromCardSecurityBytes(byte[] cardSecurityBytes) throws IOException
  {
    ASN1 seq = new ASN1(new ByteArrayInputStream(cardSecurityBytes));
    ASN1 dto = seq.getChildElements()[1];
    ASN1 signedData = new ASN1(dto.getChildElements()[0]);
    ASN1 octetString = new ASN1(signedData.getChildElements()[2].getChildElements()[1].getChildElements()[0]);
    SecurityInfos temp = new SecurityInfos(octetString.getValue());
    return (SecurityInfos)temp.decode(temp);
  }

  public static Map<String, byte[]> evaluateEFOD(byte[] content) throws IOException
  {
    Map<String, byte[]> resultMap = new HashMap<>();
    ASN1 efodASN1 = new ASN1(0x30, content);
    try
    {
      ASN1 pathOrObjects = efodASN1.getChildElementsByDTagBytes(new byte[]{(byte)0xa0})[0];
      ASN1[] path = pathOrObjects.getChildElementsByTag(0x30);
      if (path != null && path.length == 1)
      {
        resultMap.put(FID_EFPRKD, path[0].getChildElementsByTag(0x04)[0].getValue());
      }
      else
      {
        resultMap.put(PRK_ID,
                      evaluateEFPrKD(pathOrObjects.getChildElementsByDTagBytes(new byte[]{(byte)0xa0})[0]));
      }

      pathOrObjects = efodASN1.getChildElementsByDTagBytes(new byte[]{(byte)0xa4})[0];
      path = pathOrObjects.getChildElementsByTag(0x30);
      if (path != null && path.length == 1)
      {
        resultMap.put(FID_EFCD, path[0].getChildElementsByTag(0x04)[0].getValue());
      }
      else
      {
        resultMap.putAll(evaluateEFCD(pathOrObjects.getChildElementsByDTagBytes(new byte[]{(byte)0xa0})[0]));
      }

      pathOrObjects = efodASN1.getChildElementsByDTagBytes(new byte[]{(byte)0xa8})[0];
      path = pathOrObjects.getChildElementsByTag(0x30);
      if (path != null && path.length == 1)
      {
        resultMap.put(FID_EFAOD, path[0].getChildElementsByTag(0x04)[0].getValue());
      }
      else
      {
        resultMap.put(PIN_ID,
                      evaluateEFAOD(pathOrObjects.getChildElementsByDTagBytes(new byte[]{(byte)0xa0})[0]));
      }
    }
    catch (IOException e)
    {
      throw new IOException("Could not evaluate EF.OD", e);
    }
    if ((resultMap.get(FID_EFPRKD) == null && resultMap.get(PRK_ID) == null)
        || (resultMap.get(FID_EFCD) == null && (resultMap.get(FID_CACERT) == null || resultMap.get(FID_CERT) == null))
        || (resultMap.get(FID_EFAOD) == null && resultMap.get(PIN_ID) == null))
    {
      throw new IOException("Unexpected content of EF.OD");
    }
    return resultMap;
  }

  public static byte[] evaluateEFPrKD(ASN1 content) throws IOException
  {
    if (content == null)
    {
      throw new IOException("Could not read EF.PrKD");
    }

    byte[] result = null;
    try
    {
      if (content.getChildElementCount() != 1)
      {
        throw new IOException("EF.PrKD not containing exactly one private key object - unclear which to use");
      }

      ASN1 prKChoice = content.getChildElements()[0];
      result = prKChoice.getChildElementsByTag(0x30)[1].getChildElementsByTag(0x02)[0].getValue();

      // remove leading zero if present
      result = ByteUtil.removeLeadingZero(result);
    }
    catch (IOException e)
    {
      throw new IOException("Could not evaluate EF.PrKD", e);
    }
    if (result == null || result.length == 0)
    {
      throw new IOException("Could not determine ID of private key");
    }
    return result;
  }

  public static Map<String, byte[]> evaluateEFCD(ASN1 content) throws IOException
  {
    if (content == null)
    {
      throw new IOException("Could not read EF.CD");
    }

    byte[] fidCACert = null;
    byte[] fidCert = null;
    try
    {
      for ( ASN1 certDescr : content.getChildElementList() )
      {
        boolean auth = false;
        ASN1[] boolList = certDescr.getChildElementsByTag(0x30)[1].getChildElementsByTag(0x01);
        if (boolList != null && boolList.length > 0)
        {
          auth = boolList[0].getValue()[0] == (byte)0xff;
        }

        byte[] fid = certDescr.getChildElementsByDTagBytes(new byte[]{(byte)0xa1})[0].getChildElementsByTag(0x30)[0].getChildElementsByTag(0x30)[0].getChildElementsByTag(0x04)[0].getValue();
        if (auth)
        {
          fidCACert = fid;
        }
        else
        {
          fidCert = fid;
        }
      }
    }
    catch (IOException e)
    {
      throw new IOException("Could not evaluate EF.CD", e);
    }
    if (fidCert == null || fidCert.length == 0 || fidCACert == null || fidCACert.length == 0)
    {
      throw new IOException("Could not determine FIDs of certificates");
    }
    Map<String, byte[]> resultMap = new HashMap<>();
    resultMap.put(FID_CACERT, fidCACert);
    resultMap.put(FID_CERT, fidCert);
    return resultMap;
  }

  private static byte[] evaluateEFAOD(ASN1 content) throws IOException
  {
    if (content == null)
    {
      throw new IOException("Could not read EF.AOD");
    }

    byte[] result = null;
    try
    {
      if (content.getChildElementCount() != 1)
      {
        throw new IOException(
                              "EF.AOD not containing exactly one authentication key object - unclear which to use");
      }

      ASN1 aoChoice = content.getChildElements()[0];
      result = aoChoice.getChildElementsByDTagBytes(new byte[]{(byte)0xa1})[0].getChildElements()[0].getChildElementsByDTagBytes(new byte[]{(byte)0x80})[0].getValue();

      // remove leading zero if present
      result = ByteUtil.removeLeadingZero(result);
    }
    catch (IOException e)
    {
      throw new IOException("Could not evaluate EF.AOD", e);
    }
    if (result == null || result.length == 0)
    {
      throw new IOException("Could not determine ID of PIN");
    }
    return result;
  }

  public static byte[] evaluateFCP(byte[] content) throws IOException
  {
    if (ArrayUtil.isNullOrEmpty(content))
    {
      throw new IOException("Could not get FCP of certificate file");
    }
    try
    {
      ASN1 fcp = new ASN1(content);
      return fcp.getChildElementsByDTagBytes(new byte[]{(byte)0x80})[0].getValue();
    }
    catch (IOException e)
    {
      throw new IOException("Could not get information about certificate file", e);
    }
  }
}

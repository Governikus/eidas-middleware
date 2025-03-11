/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardbase.asn1.npa.si;

import static de.governikus.eumw.poseidas.cardbase.asn1.npa.si.SecurityInfoConstants.MESSAGE_CAN_NOT_CONVERT_TO_STRING;
import static de.governikus.eumw.poseidas.cardbase.asn1.npa.si.SecurityInfoConstants.STRING_NOT_GIVEN;
import static de.governikus.eumw.poseidas.cardbase.asn1.npa.si.SecurityInfoConstants.STRING_PROTOCOL;

import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

import de.governikus.eumw.poseidas.cardbase.Hex;
import de.governikus.eumw.poseidas.cardbase.asn1.ASN1;
import de.governikus.eumw.poseidas.cardbase.asn1.OID;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.SecurityInfos;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.SecurityInfosPath;


/**
 * Implementation of the <code>CardInfo</code> structure in {@link SecurityInfos}.
 *
 * @author Arne Stahlbock, ast@bos-bremen.de
 */
public class CardInfo extends SecurityInfo
{

  /**
   * Constructor.
   *
   * @param bytes byte-array containing ASN.1 description of a {@link CardInfo}.
   * @throws IOException if reading bytes fails
   */
  public CardInfo(byte[] bytes) throws IOException
  {
    super(bytes);
  }

  /**
   * Gets the child element <code>urlCardInfo</code> converted to {@link String}.
   *
   * @return {@link String} containing <code>urlCardInfo</code>
   * @throws IOException
   */
  public String getUrlCardInfo() throws IOException
  {
    return super.getString(SecurityInfosPath.CARD_INFO_URL);
  }

  /**
   * Gets the child element <code>OptionalCardInfoData</code>.
   *
   * @return {@link ASN1} instance containing <code>EFCardInfo</code> or <code>ExtCardInfoData</code>,
   *         <code>null</code> possible
   * @throws IOException if error in getting
   */
  public ASN1 getInnerElement() throws IOException
  {
    return super.getChildElementByPath(SecurityInfosPath.CARD_INFO_INNER_SEQ);
  }

  public byte[] getFID() throws IOException
  {
    ASN1 fid = super.getChildElementByPath(SecurityInfosPath.CARD_INFO_INNER_FILEID_FID);
    if (fid == null)
    {
      fid = super.getChildElementByPath(SecurityInfosPath.CARD_INFO_INNER_EXTCID_FID);
    }
    if (fid == null)
    {
      return null;
    }
    return fid.getValue();
  }

  public byte[] getSFID() throws IOException
  {
    ASN1 sfid = super.getChildElementByPath(SecurityInfosPath.CARD_INFO_INNER_FILEID_SFID);
    if (sfid == null)
    {
      sfid = super.getChildElementByPath(SecurityInfosPath.CARD_INFO_INNER_EXTCID_SFID);
    }
    if (sfid == null)
    {
      return null;
    }
    return sfid.getValue();
  }

  public String getSupportedTRVersion() throws IOException
  {
    return super.getStringNull(SecurityInfosPath.CARD_INFO_INNER_EXTCID_TRVERSION);
  }

  public Set<SupportedTerminalTypes> getSupportedTerminalTypesSet() throws IOException
  {
    ASN1 asn1 = super.getChildElementByPath(SecurityInfosPath.CARD_INFO_INNER_EXTCID_TERMTYPES);
    if (asn1 == null)
    {
      return null;
    }
    Set<SupportedTerminalTypes> result = new HashSet<>();
    for ( ASN1 child : asn1.getChildElementList() )
    {
      result.add(new SupportedTerminalTypes(child.getEncoded()));
    }
    return result;
  }

  public Integer getMaxSCNo() throws IOException
  {
    return super.getInteger(SecurityInfosPath.CARD_INFO_INNER_EXTCID_MAXSC);
  }

  public Boolean getEnvInfo() throws IOException
  {
    ASN1 envInfo = super.getChildElementByPath(SecurityInfosPath.CARD_INFO_INNER_EXTCID_ENVINFO);
    if (envInfo == null)
    {
      return null;
    }
    return envInfo.getValue()[0] == 0xff;
  }

  /** {@inheritDoc} */
  @Override
  public String toString()
  {
    StringBuilder result = new StringBuilder();
    result.append("CardInfo: ");
    ASN1 efCardInfo = null;
    try
    {
      result.append(STRING_PROTOCOL);
      result.append(super.getProtocol());
      result.append("\n-- urlCardInfo ");
      result.append(this.getUrlCardInfo());
      efCardInfo = this.getInnerElement();
    }
    catch (IOException e)
    {
      throw new IllegalStateException(MESSAGE_CAN_NOT_CONVERT_TO_STRING, e);
    }
    result.append("\n-- optionalCardInfoData ");
    result.append(efCardInfo != null ? ("\n" + Hex.hexify(efCardInfo.getValue())) : STRING_NOT_GIVEN);
    return result.toString();
  }


  /**
   * Implementation of the <code>SupportedTerminalTypes</code> structure in {@link SecurityInfos}.
   *
   * @author Arne Stahlbock, ast@bos-bremen.de
   */
  public static class SupportedTerminalTypes extends ASN1
  {

    private SupportedTerminalTypes(byte[] bytes) throws IOException
    {
      super(bytes);
    }

    public OID getSupportedTerminalType() throws IOException
    {
      return (OID)super.getChildElementByPath(SecurityInfosPath.SUPPORTED_TERMINAL_TYPES_TERMINAL_TYPE);
    }

    public Set<OID> getSupportedAuthorizationsSet() throws IOException
    {
      ASN1 asn1 = super.getChildElementByPath(SecurityInfosPath.SUPPORTED_TERMINAL_TYPES_AUTHORIZATIONS);
      if (asn1 == null)
      {
        return null;
      }
      Set<OID> result = new HashSet<>();
      for ( ASN1 child : asn1.getChildElementList() )
      {
        result.add(new OID(child.getEncoded()));
      }
      return result;
    }
  }
}

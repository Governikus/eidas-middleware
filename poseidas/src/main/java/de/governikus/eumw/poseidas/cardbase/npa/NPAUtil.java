/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardbase.npa;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;

import de.governikus.autent.asn1.si.SecurityInfos;


/**
 * Utility class used in nPA context. (Separated from NPAUtil in client as this is also required on server side.)
 *
 * @author Arne Stahlbock, ast@bos-bremen.de
 */
public class NPAUtil
{

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
    // parse CMS SignedData
    ContentInfo contentInfo = ContentInfo.getInstance(cardSecurityBytes);
    SignedData signedData = SignedData.getInstance(contentInfo.getContent());
    ASN1Encodable content = signedData.getEncapContentInfo().getContent();

    // extract OCTET string
    ASN1OctetString octetString = ASN1OctetString.getInstance(content);

    // parse security infos
    return new SecurityInfos(octetString.getOctets());
  }
}

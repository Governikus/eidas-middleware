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

import java.io.IOException;

import de.governikus.eumw.poseidas.cardbase.asn1.ASN1;
import de.governikus.eumw.poseidas.cardbase.asn1.OID;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.SecurityInfosPath;


/**
 * Abstract implementation of the <code>SecurityInfo</code> structure, a base for several other structures in
 * EFCardAccess / EFCardSecurity.
 *
 * @author Arne Stahlbock, ast@bos-bremen.de
 */
abstract class SecurityInfo extends ASN1
{

  /**
   * Constructor.
   *
   * @param bytes byte-array containing ASN.1 description of a {@link SecurityInfo}
   * @throws IOException if reading bytes fails
   */
  public SecurityInfo(byte[] bytes) throws IOException
  {
    super(bytes);
  }

  /**
   * Gets the child element <code>protocol</code> present in every {@link SecurityInfo}.
   *
   * @return {@link OID} instance containing <code>protocol</code>, <code>null</code> possible
   * @throws IOException if error in getting
   */
  public final OID getProtocol() throws IOException
  {
    return (OID)super.getChildElementByPath(SecurityInfosPath.SECURITY_INFO_PROTOCOL);
  }
}

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

import java.io.IOException;

import de.governikus.eumw.poseidas.cardbase.Hex;
import de.governikus.eumw.poseidas.cardbase.asn1.ASN1;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.SecurityInfosPath;


/**
 * Implementation of the <code>DataGroupHash</code> structure in {@link EIDSecurityObject}.
 *
 * @author Arne Stahlbock, ast@bos-bremen.de
 */
public class DataGroupHash extends ASN1
{

  /**
   * Constructor.
   *
   * @param bytes byte-array containing ASN.1 description of a {@link DataGroupHash}.
   * @throws IOException if reading bytes fails
   */
  DataGroupHash(byte[] bytes) throws IOException
  {
    super(bytes);
  }

  /**
   * Gets data group number.
   *
   * @return data group number
   * @throws IOException
   */
  public int getDataGroupNumber() throws IOException
  {
    return super.getInt(SecurityInfosPath.DATA_GROUP_HASH_NUMBER);
  }

  /**
   * Gets data group hash.
   *
   * @return data group hash
   * @throws IOException
   */
  public byte[] getDataGroupHashValue() throws IOException
  {
    return super.getChildElementByPath(SecurityInfosPath.DATA_GROUP_HASH_VALUE).getValue();
  }

  /** {@inheritDoc} */
  @Override
  public String toString()
  {
    StringBuilder result = new StringBuilder();
    result.append("\n---- dataGroupHash: \n------ dataGroupNumber ");
    try
    {
      result.append(this.getDataGroupNumber());
      result.append("\n------ dataGroupHashValue ");
      result.append(Hex.hexify(this.getDataGroupHashValue()));
    }
    catch (IOException e)
    {
      throw new IllegalStateException(MESSAGE_CAN_NOT_CONVERT_TO_STRING, e);
    }
    return result.toString();
  }
}

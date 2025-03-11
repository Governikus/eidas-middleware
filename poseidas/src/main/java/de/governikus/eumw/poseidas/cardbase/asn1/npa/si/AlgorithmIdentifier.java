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

import java.io.IOException;

import de.governikus.eumw.poseidas.cardbase.Hex;
import de.governikus.eumw.poseidas.cardbase.asn1.ASN1;
import de.governikus.eumw.poseidas.cardbase.asn1.ASN1Constants;
import de.governikus.eumw.poseidas.cardbase.asn1.AbstractASN1Encoder;
import de.governikus.eumw.poseidas.cardbase.asn1.OID;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.SecurityInfos;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.SecurityInfosPath;


/**
 * Implementation of the <code>AlgorithmIdentifier</code> structure in {@link SecurityInfos}.
 *
 * @author Arne Stahlbock, ast@bos-bremen.de
 */
public class AlgorithmIdentifier extends AbstractASN1Encoder
{

  public AlgorithmIdentifier() throws IOException
  {
    super(new byte[]{ASN1Constants.UNIVERSAL_TAG_SEQUENCE_CONSTRUCTED, 0x00});
  }

  /**
   * Constructor.
   *
   * @param bytes byte-array containing ASN.1 description of a {@link AlgorithmIdentifier}.
   * @throws IOException if reading bytes fails
   */
  public AlgorithmIdentifier(byte[] bytes) throws IOException
  {
    super(bytes);
  }

  /**
   * Gets the child element <code>algorithm</code>.
   *
   * @return {@link OID} instance containing <code>algorithm</code>, <code>null</code> possible
   * @throws IOException if error in getting
   */
  public OID getAlgorithm() throws IOException
  {
    return (OID)super.getChildElementByPath(SecurityInfosPath.ALGORITHM_IDENTIFIER_ALGORITHM);
  }

  /**
   * Gets the child element <code>parameters</code>.
   *
   * @return {@link ASN1} instance containing <code>parameters</code>, <code>null</code> possible
   * @throws IOException if error in getting
   */
  public ASN1 getParameters() throws IOException
  {
    ASN1 result = super.getChildElementByPath(SecurityInfosPath.ALGORITHM_IDENTIFIER_PARAMETERS);
    if (result == null)
    {
      result = super.getChildElementByPath(SecurityInfosPath.ALGORITHM_IDENTIFIER_PARAMETER_ID);
    }
    return result;
  }

  /**
   * Gets ID of standardized domain parameters if applicable.
   *
   * @return ID of standardized domain parameters, <code>null</code> if explicit parameters used
   * @throws IOException
   */
  public Integer getParameterID() throws IOException
  {
    return super.getInteger(SecurityInfosPath.ALGORITHM_IDENTIFIER_PARAMETER_ID);
  }

  /** {@inheritDoc} */
  @Override
  public String toString()
  {
    StringBuilder result = new StringBuilder();
    ASN1 parameters = null;
    result.append("\n-- AlgorithmIdentifier: \n---- algorithm ");
    try
    {
      result.append(this.getAlgorithm().toString());
      parameters = this.getParameters();
    }
    catch (IOException e)
    {
      throw new IllegalStateException(MESSAGE_CAN_NOT_CONVERT_TO_STRING, e);
    }
    result.append("\n---- parameters ");
    result.append(parameters != null ? Hex.hexify(parameters.getValue()) : STRING_NOT_GIVEN);
    return result.toString();
  }
}

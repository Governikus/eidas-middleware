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
import java.util.ArrayList;
import java.util.List;

import de.governikus.eumw.poseidas.cardbase.Hex;
import de.governikus.eumw.poseidas.cardbase.asn1.ASN1;
import de.governikus.eumw.poseidas.cardbase.asn1.ASN1Constants;
import de.governikus.eumw.poseidas.cardbase.asn1.AbstractASN1Encoder;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.SecurityInfosPath;


/**
 * Implementation of the <code>eIDSecurityObject</code> structure in {@link EIDSecurityInfo}.
 *
 * @author Arne Stahlbock, ast@bos-bremen.de
 */
public class EIDSecurityObject extends AbstractASN1Encoder
{

  /**
   * <code>hashAlgorithm</code> element.
   */
  private AlgorithmIdentifier hashAlgorithm;

  /**
   * <code>dataGroupHashValues</code> element.
   */
  private List<DataGroupHash> dataGroupHashValues;


  public EIDSecurityObject() throws IOException
  {
    super(ASN1Constants.UNIVERSAL_TAG_SEQUENCE_CONSTRUCTED, new byte[0]);
  }

  /**
   * Gets the child element <code>hashAlgorithm</code>.
   *
   * @return {@link AlgorithmIdentifier} instance
   * @throws IOException if error in getting
   */
  public AlgorithmIdentifier getHashAlgorithm() throws IOException
  {
    if (this.hashAlgorithm == null)
    {
      this.hashAlgorithm = (AlgorithmIdentifier)super.getChildElementByPath(SecurityInfosPath.EID_SECURITY_INFO_OBJECT_HASH_ALG);
    }
    return this.hashAlgorithm;
  }

  /**
   * Gets the child element <code>dataGroupHashValues</code> as a list of {@link DataGroupHash}.
   *
   * @return list of {@link DataGroupHash}
   * @throws IOException if error in getting
   */
  public List<DataGroupHash> getDataGroupHashValues() throws IOException
  {
    if (this.dataGroupHashValues == null)
    {
      this.dataGroupHashValues = new ArrayList<>();
      ASN1 sequence = new ASN1(super.getChildElementByPath(SecurityInfosPath.EID_SECURITY_INFO_OBJECT_HASH_VALUES));
      for ( ASN1 child : sequence.getChildElements() )
      {
        this.dataGroupHashValues.add(new DataGroupHash(child.getEncoded()));
      }
    }
    return this.dataGroupHashValues;
  }

  /** {@inheritDoc} */
  @Override
  public String toString()
  {
    StringBuilder result = new StringBuilder();
    result.append("\n-- EIDSecurityObject: \n---- hashAlgorithm ");
    try
    {
      result.append(Hex.hexify(this.getHashAlgorithm().getValue()));
      for ( DataGroupHash hash : this.getDataGroupHashValues() )
      {
        result.append(hash);
      }
    }
    catch (IOException e)
    {
      throw new IllegalStateException(MESSAGE_CAN_NOT_CONVERT_TO_STRING, e);
    }
    return result.toString();
  }

  @Override
  protected void update()
  {
    this.hashAlgorithm = null;
    this.dataGroupHashValues = null;
  }

  @Override
  public boolean equals(Object object)
  {
    return super.equals(object);
  }

  @Override
  public int hashCode()
  {
    return super.hashCode();
  }
}

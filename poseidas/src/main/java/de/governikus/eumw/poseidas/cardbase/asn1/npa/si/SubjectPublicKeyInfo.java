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
import de.governikus.eumw.poseidas.cardbase.asn1.ASN1Constants;
import de.governikus.eumw.poseidas.cardbase.asn1.AbstractASN1Encoder;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.SecurityInfos;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.SecurityInfosPath;


/**
 * Implementation of the <code>SubjectPublicKeyInfo</code> structure in {@link SecurityInfos}.
 *
 * @author Arne Stahlbock, ast@bos-bremen.de
 */
public class SubjectPublicKeyInfo extends AbstractASN1Encoder
{

  /**
   * Reference to the <code>algorithm</code> child element.
   */
  private AlgorithmIdentifier algorithm;


  public SubjectPublicKeyInfo() throws IOException
  {
    super(new byte[]{ASN1Constants.UNIVERSAL_TAG_SEQUENCE_CONSTRUCTED, 0x00});
  }

  /**
   * Gets the child element <code>algorithm</code>.
   *
   * @return {@link AlgorithmIdentifier} instance containing <code>algorithm</code>, <code>null</code>
   *         possible
   * @throws IOException if error in getting
   */
  public AlgorithmIdentifier getAlgorithm() throws IOException
  {
    if (this.algorithm == null)
    {
      this.algorithm = (AlgorithmIdentifier)super.getChildElementByPath(SecurityInfosPath.SUBJECT_PUBLIC_KEY_INFO_ALGORITHM);
    }
    return this.algorithm;
  }

  /**
   * Gets the child element <code>subjectPublicKey</code>.
   *
   * @return {@link ASN1} instance containing <code>subjectPublicKey</code>, <code>null</code> possible
   * @throws IOException if error in getting
   */
  public ASN1 getSubjectPublicKey() throws IOException
  {
    return super.getChildElementByPath(SecurityInfosPath.SUBJECT_PUBLIC_KEY_INFO_SUBJECT_PUBLIC_KEY);
  }

  /** {@inheritDoc} */
  @Override
  public String toString()
  {
    StringBuilder result = new StringBuilder();
    result.append("\n-- SubjectPublicKeyInfo: ");
    try
    {
      result.append(this.getAlgorithm());
      result.append("\n---- public key: ");
      result.append(Hex.hexify(this.getSubjectPublicKey().getValue()));
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
    this.algorithm = null;
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

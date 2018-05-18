/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.eidserver.convenience;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import de.governikus.eumw.poseidas.cardbase.AssertUtil;
import de.governikus.eumw.poseidas.cardbase.ByteUtil;
import de.governikus.eumw.poseidas.cardbase.Hex;
import de.governikus.eumw.poseidas.cardbase.asn1.ASN1;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.si.AlgorithmIdentifier;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.si.PSPublicKeyInfo;
import de.governikus.eumw.poseidas.cardserver.eac.functions.ps.PseudonymousSignatureParameter;


public class EIDInfoResultPseudonymousSignature extends EIDInfoResultRestrictedID implements EIDInfoResult
{

  private static final long serialVersionUID = 2L;

  private final byte[] signature;

  private final byte[] domainParameters;

  private final byte[] pkM;

  private final byte[] pkICC;

  private final byte[] pkSector;

  private final byte[] idDSI;

  private final byte[] message;

  private final Boolean verified;

  EIDInfoResultPseudonymousSignature(byte[] id1,
                                            byte[] id2,
                                            byte[] signature,
                                            PseudonymousSignatureParameter parameter,
                                            Boolean verified) throws IOException
  {
    super(id1, id2);
    AssertUtil.notNullOrEmpty(signature, "signature bytes");
    AssertUtil.notNull(parameter, "signature parameter");

    this.signature = signature;
    PSPublicKeyInfo psPublicKeyInfo = parameter.getPsPubKeyInfo();
    AlgorithmIdentifier outerAlgId = psPublicKeyInfo.getpSPublicKey().getAlgorithm();
    List<ASN1> childList = outerAlgId.getParameters().getChildElementList();
    this.domainParameters = childList.get(0).getEncoded();
    this.pkM = childList.get(1).getValue();
    this.pkICC = ByteUtil.removeLeadingZero(psPublicKeyInfo.getpSPublicKey().getSubjectPublicKey().getValue());
    this.pkSector = parameter.getPseudonymousSignatureKey();
    this.idDSI = parameter.getPsInfo().getProtocol().getValue();
    this.message = parameter.getSignatureInput();
    this.verified = verified;
  }

  public byte[] getSignature()
  {
    return this.signature;
  }

  public byte[] getMessage()
  {
    return this.message;
  }

  public byte[] getDomainParameters()
  {
    return this.domainParameters;
  }

  public byte[] getPkM()
  {
    return this.pkM;
  }

  public byte[] getPkICC()
  {
    return this.pkICC;
  }

  public byte[] getPkSector()
  {
    return this.pkSector;
  }

  public byte[] getIdDSI()
  {
    return this.idDSI;
  }

  public Boolean getVerified()
  {
    return this.verified;
  }

  @Override
  public int hashCode()
  {
    final int prime = 31;
    return prime * super.hashCode() + Arrays.hashCode(this.getSignature());
  }

  @Override
  public boolean equals(Object obj)
  {
    if (this == obj)
    {
      return true;
    }
    if (obj == null || getClass() != obj.getClass())
    {
      return false;
    }
    EIDInfoResultPseudonymousSignature other = (EIDInfoResultPseudonymousSignature)obj;
    if (!Arrays.equals(super.getID1(), other.getID1()))
    {
      return false;
    }
    if (!Arrays.equals(super.getID2(), other.getID2()))
    {
      return false;
    }
    if (!Arrays.equals(this.signature, other.getSignature()))
    {
      return false;
    }
    return true;
  }

  @Override
  public String toString()
  {
    StringBuilder builder = new StringBuilder();
    builder.append(super.toString());
    builder.append(" signature: ");
    if (this.signature != null)
    {
      builder.append(Hex.hexify(this.signature));
    }
    else
    {
      builder.append("null");
    }
    return builder.toString();
  }
}

/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardbase.crypto;

import de.governikus.eumw.poseidas.cardbase.asn1.OID;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;


/**
 * Enum with known hash algorithms.
 *
 * @see HashAlgorithm
 * @see HashConstants
 * @see HashInfo
 * @author Jens Wothe, jw@bos-bremen.de
 */
@Getter
@AllArgsConstructor(access = AccessLevel.PRIVATE)
enum HashAlgorithmEnum implements HashInfo
{

  /**
   * SHA1.
   *
   * @see HashConstants#SHA1_ALGORITHM
   */
  SHA1(HashConstants.SHA1_ALGORITHM),
  /**
   * SHA224.
   *
   * @see HashConstants#SHA224_ALGORITHM
   */
  SHA224(HashConstants.SHA224_ALGORITHM),
  /**
   * SHA526.
   *
   * @see HashConstants#SHA256_ALGORITHM
   */
  SHA256(HashConstants.SHA256_ALGORITHM),
  /**
   * SHA384.
   *
   * @see HashConstants#SHA384_ALGORITHM
   */
  SHA384(HashConstants.SHA384_ALGORITHM),
  /**
   * SHA512.
   *
   * @see HashConstants#SHA512_ALGORITHM
   */
  SHA512(HashConstants.SHA512_ALGORITHM);

  // algorithm
  private HashAlgorithm hashAlgorithm = null;

  /** {@inheritDoc} */
  @Override
  public String getName()
  {
    return hashAlgorithm.getName();
  }

  /** {@inheritDoc} */
  @Override
  public String getOIDString()
  {
    return hashAlgorithm.getOIDString();
  }

  /** {@inheritDoc} */
  @Override
  public OID getOID()
  {
    return hashAlgorithm;
  }

  /** {@inheritDoc} */
  @Override
  public int getHashLength()
  {
    return hashAlgorithm.getHashLength();
  }

  /** {@inheritDoc} */
  @Override
  public byte[] getOIDValue()
  {
    return hashAlgorithm.getOIDValue();
  }

  /** {@inheritDoc} */
  @Override
  public byte[] getEncoded()
  {
    return hashAlgorithm.getEncoded();
  }
}

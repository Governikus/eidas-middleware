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

import org.bouncycastle.asn1.x509.DigestInfo;

import lombok.experimental.UtilityClass;


/**
 * Constants related to algorithm.
 *
 * @see DigestInfo
 * @see HashAlgorithmEnum
 * @author Jens Wothe, jw@bos-bremen.de
 */
@UtilityClass
public final class HashConstants
{

  /**
   * JCE name of SHA1.
   *
   * @see #SHA1_ALGORITHM
   */
  public static final String SHA1_JCE_NAME = "SHA-1";

  /**
   * JCE name of SHA224.
   *
   * @see #SHA224_ALGORITHM
   */
  public static final String SHA224_JCE_NAME = "SHA-224";

  /**
   * JCE name of SHA256.
   *
   * @see #SHA256_ALGORITHM
   */
  public static final String SHA256_JCE_NAME = "SHA-256";

  /**
   * JCE name of SHA384.
   *
   * @see #SHA384_ALGORITHM
   */
  public static final String SHA384_JCE_NAME = "SHA-384";

  /**
   * JCE name of SHA512.
   *
   * @see #SHA512_ALGORITHM
   */
  public static final String SHA512_JCE_NAME = "SHA-512";

  /**
   * OID of SHA1: 1.3.14.3.2.26.
   *
   * @see #SHA1_ALGORITHM
   */
  public static final String SHA1_OID_STRING = "1.3.14.3.2.26";

  /**
   * OID of SHA224: 2.16.840.1.101.3.4.2.4.
   *
   * @see #SHA224_ALGORITHM
   */
  public static final String SHA224_OID_STRING = "2.16.840.1.101.3.4.2.4";

  /**
   * OID of SHA256: 2.16.840.1.101.3.4.2.1.
   *
   * @see #SHA256_ALGORITHM
   */
  public static final String SHA256_OID_STRING = "2.16.840.1.101.3.4.2.1";

  /**
   * OID of SHA384: 2.16.840.1.101.3.4.2.2.
   *
   * @see #SHA384_ALGORITHM
   */
  public static final String SHA384_OID_STRING = "2.16.840.1.101.3.4.2.2";

  /**
   * OID of SHA512: 2.16.840.1.101.3.4.2.3.
   *
   * @see #SHA512_ALGORITHM
   */
  public static final String SHA512_OID_STRING = "2.16.840.1.101.3.4.2.3";

  /**
   * Length of SHA1-hash: 20.
   *
   * @see #SHA1_ALGORITHM
   */
  public static final int SHA1_LENGTH_HASH = 20;

  /**
   * Length of SHA224-hash: 28.
   *
   * @see #SHA224_ALGORITHM
   */
  public static final int SHA224_LENGTH_HASH = 28;

  /**
   * Length of SHA256-hash: 32.
   *
   * @see #SHA256_ALGORITHM
   */
  public static final int SHA256_LENGTH_HASH = 32;

  /**
   * Length of SHA384-hash: 48.
   *
   * @see #SHA384_ALGORITHM
   */
  public static final int SHA384_LENGTH_HASH = 48;

  /**
   * Length of SHA512-hash: 64.
   *
   * @see #SHA512_ALGORITHM
   */
  public static final int SHA512_LENGTH_HASH = 64;

  /**
   * SHA1-Algorithm.
   *
   * @see #SHA1_JCE_NAME
   * @see #SHA1_LENGTH_HASH
   * @see #SHA1_OID_STRING
   */
  public static final HashAlgorithm SHA1_ALGORITHM = new HashAlgorithm(SHA1_JCE_NAME, SHA1_LENGTH_HASH,
                                                                       SHA1_OID_STRING);

  /**
   * SHA224-Algorithm.
   *
   * @see #SHA224_JCE_NAME
   * @see #SHA224_LENGTH_HASH
   * @see #SHA224_OID_STRING
   */
  public static final HashAlgorithm SHA224_ALGORITHM = new HashAlgorithm(SHA224_JCE_NAME, SHA224_LENGTH_HASH,
                                                                         SHA224_OID_STRING);

  /**
   * SHA256-Algorithm.
   *
   * @see #SHA256_JCE_NAME
   * @see #SHA256_LENGTH_HASH
   * @see #SHA256_OID_STRING
   */
  public static final HashAlgorithm SHA256_ALGORITHM = new HashAlgorithm(SHA256_JCE_NAME, SHA256_LENGTH_HASH,
                                                                         SHA256_OID_STRING);

  /**
   * SHA384-Algorithm.
   *
   * @see #SHA384_JCE_NAME
   * @see #SHA384_LENGTH_HASH
   * @see #SHA384_OID_STRING
   */
  public static final HashAlgorithm SHA384_ALGORITHM = new HashAlgorithm(SHA384_JCE_NAME, SHA384_LENGTH_HASH,
                                                                         SHA384_OID_STRING);

  /**
   * SHA512-Algorithm.
   *
   * @see #SHA512_JCE_NAME
   * @see #SHA512_LENGTH_HASH
   * @see #SHA512_OID_STRING
   */
  public static final HashAlgorithm SHA512_ALGORITHM = new HashAlgorithm(SHA512_JCE_NAME, SHA512_LENGTH_HASH,
                                                                         SHA512_OID_STRING);
}

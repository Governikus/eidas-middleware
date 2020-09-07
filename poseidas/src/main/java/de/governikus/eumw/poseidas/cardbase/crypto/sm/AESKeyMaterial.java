/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardbase.crypto.sm;

import javax.crypto.SecretKey;

import de.governikus.eumw.poseidas.cardbase.AssertUtil;
import de.governikus.eumw.poseidas.cardbase.crypto.CipherUtil;


/**
 * Implementation of key material based on AES keys used for data field encryption and CMAC calculation as it
 * is used for nPA.
 *
 * @author Arne Stahlbock, ast@bos-bremen.de
 * @author Jens Wothe, jw@bos-bremen.de
 */
public class AESKeyMaterial
{

  private final AESEncSSCIvParameterSpec ivParameterSpecSSC;

  private final SecretKey aes3EncKey;

  private final SecretKey aes3MacKey;

  /**
   * Constructor.
   *
   * @param aesEncKey AES key for encryption and decryption of data field, <code>null</code> or keys other
   *          than AES not permitted, encryption key and mac calculation key must be of same strength
   * @param aesMacKey AES key for CMAC calculation, <code>null</code> or keys other than AES not permitted,
   *          encryption key and mac calculation key must be of same strength
   * @param ivParameterSpecSSC IvParameterSpec as SSC related parameter spec, <code>null</code> not permitted
   *          permitted
   * @throws IllegalArgumentException if keys or IvParameterSpec not permitted, also if keys of different
   *           strength used
   */
  public AESKeyMaterial(SecretKey aesEncKey, SecretKey aesMacKey, AESEncSSCIvParameterSpec ivParameterSpecSSC)
  {
    super();
    AssertUtil.notNull(aesEncKey, "encryption key");
    AssertUtil.notNull(aesMacKey, "Mac key");
    AssertUtil.notNull(ivParameterSpecSSC, "IVParameterSpec of SSC");
    if (!CipherUtil.ALGORITHM_AES.equals(aesEncKey.getAlgorithm()))
    {
      throw new IllegalArgumentException("only AES key permitted for encryption");
    }
    if (!CipherUtil.ALGORITHM_AES.equals(aesMacKey.getAlgorithm()))
    {
      throw new IllegalArgumentException("only AES key permitted for MAC calculation");
    }
    if (aesEncKey.getEncoded().length != aesMacKey.getEncoded().length)
    {
      throw new IllegalArgumentException(
                                         "AES keys for encryption and mac calculation not consistent, different strength");
    }
    if (CipherUtil.AES_IV_LENGTH != ivParameterSpecSSC.getLength())
    {
      throw new IllegalArgumentException("only IvParameterSpec with " + CipherUtil.AES_IV_LENGTH
                                         + " bytes permitted");
    }
    this.aes3EncKey = aesEncKey;
    this.aes3MacKey = aesMacKey;
    this.ivParameterSpecSSC = ivParameterSpecSSC;
  }

  /**
   * Gets the IvParameterSpec for MAC calculation.
   *
   * @return the sscIvParameterSpec
   */
  public AESEncSSCIvParameterSpec getIvParameterSpec()
  {
    return this.ivParameterSpecSSC;
  }

  /**
   * Gets AES key for encryption and decryption of data field.
   *
   * @return the AES key
   */
  public SecretKey getAESEncKey()
  {
    return aes3EncKey;
  }

  /**
   * Gets AES key for CMAC calculation.
   *
   * @return the AES key for MAC calculation
   */
  public SecretKey getAESMacKey()
  {
    return aes3MacKey;
  }
}

/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardbase.asn1.npa;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import de.governikus.eumw.poseidas.cardbase.asn1.ASN1;
import de.governikus.eumw.poseidas.cardbase.asn1.ASN1Path;
import de.governikus.eumw.poseidas.cardbase.asn1.AbstractASN1Encoder;
import de.governikus.eumw.poseidas.cardbase.asn1.OID;


/**
 * ASN.1 structure for ECPublicKey.
 * 
 * @author Arne Stahlbock, ast@bos-bremen.de
 */
public class ECPublicKey extends AbstractASN1Encoder
{

  /**
   * Constant: child count indicating long form of ECPublicKey: <code>8</code>.
   */
  private static final int CHILD_COUNT_LONG_2 = 8;

  /**
   * Constant: child count indicating long form of ECPublicKey: <code>7</code>.
   */
  private static final int CHILD_COUNT_LONG_1 = 7;

  /**
   * Constant: child count indicating short form of ECPublicKey: <code>3</code>.
   */
  private static final int CHILD_COUNT_SHORT_2 = 3;

  /**
   * Constant: child count indicating short form of ECPublicKey: <code>2</code>.
   */
  private static final int CHILD_COUNT_SHORT_1 = 2;

  /**
   * Constant child index of OID for short and long form of ECPublicKey (required): <code>0</code>.
   */
  private static final int IDX_CHILD_OID = 0;

  /**
   * Constant child index of public point Y for short form of ECPublicKey (required): <code>1</code>.
   */
  private static final int IDX_SHORT_PUBLIC_POINT_Y = 1;

  /**
   * Constant child index of cofactor F for short form of ECPublicKey (optional): <code>2</code>.
   */
  private static final int IDX_SHORT_CO_FACTOR_F = 2;

  /**
   * Constant child index of cofactor F for full form of ECPublicKey (optional): <code>7</code>.
   */
  private static final int IDX_FULL_CO_FACTOR_F = 7;

  /**
   * Constant child index of public point Y for full form of ECPublicKey (required): <code>6</code>.
   */
  private static final int IDX_FULL_PUBLIC_POINT_Y = 6;

  /**
   * Constant child index of base point order for full form of ECPublicKey (required): <code>5</code>.
   */
  private static final int IDX_FULL_ORDER_BASE_POINT = 5;

  /**
   * Constant child index of base point for full form of ECPublicKey (required): <code>4</code>.
   */
  private static final int IDX_FULL_BASE_POINT = 4;

  /**
   * Constant child index of coefficient B for full form of ECPublicKey (required): <code>3</code>.
   */
  private static final int IDX_FULL_COEFFICIENT_B = 3;

  /**
   * Constant child index of coefficient A for full form of ECPublicKey (required): <code>2</code>.
   */
  private static final int IDX_FULL_COEFFICIENT_A = 2;

  /**
   * Constant child index of prime modulus for full form of ECPublicKey (required): <code>1</code>.
   */
  private static final int IDX_FULL_PRIME_MODULUS = 1;

  /**
   * Error message to use when given ASN.1 structure is not an EC public key.
   */
  private static final String ERROR_MESSAGE_NO_EC_PUBLIC_KEY = "ASN.1 does not represent an EC public key";

  /**
   * Default Encoder Constructor.
   * 
   * @throws IOException if parsing fails
   */
  public ECPublicKey() throws IOException
  {
    super(ECPublicKeyPath.EC_PUBLIC_KEY.getTag().toByteArray(), new byte[0]);
  }

  /**
   * Constructor.
   * 
   * @param bytes bytes of complete key, <code>null</code> or empty not permitted
   * @throws IOException if reading of stream fails
   * @throws IllegalArgumentException if bytes <code>null</code> or empty or if bytes contain structure not
   *           complying with key structure.
   * @see ASN1#ASN1(byte[])
   */
  public ECPublicKey(byte[] bytes) throws IOException
  {
    super(bytes);
    check();
  }

  /**
   * Checks if key structure requirements are fulfilled.
   * 
   * @throws IllegalArgumentException if requirements not fulfilled
   */
  private void check()
  {
    if (!Arrays.equals(ECPublicKeyPath.EC_PUBLIC_KEY.getTag().toByteArray(), this.getDTagBytes()))
    {
      throw new IllegalArgumentException(ERROR_MESSAGE_NO_EC_PUBLIC_KEY);
    }
    try
    {
      List<ASN1> childList = this.getChildElementList();
      // first element is always oid
      if (!Arrays.equals(ECPublicKeyPath.OID.getTag().toByteArray(), childList.get(IDX_CHILD_OID)
                                                                              .getDTagBytes()))
      {
        throw new IllegalArgumentException(ERROR_MESSAGE_NO_EC_PUBLIC_KEY);
      }
      // according to form check short or long format
      int size = childList.size();
      if (size == CHILD_COUNT_SHORT_1 || size == CHILD_COUNT_SHORT_2)
      {
        // check short form
        checkShort(childList, size);
      }
      else if (size == CHILD_COUNT_LONG_1 || size == CHILD_COUNT_LONG_2)
      {
        // check long form
        checkLong(childList, size);
      }
      else
      {
        // size not ok
        throw new IllegalArgumentException(ERROR_MESSAGE_NO_EC_PUBLIC_KEY);
      }
    }
    catch (IOException e)
    {
      throw new IllegalArgumentException(ERROR_MESSAGE_NO_EC_PUBLIC_KEY, e);
    }
  }

  /**
   * Checks full form of public key with all curve point and optional cofactor.
   * 
   * @param childList list of children
   * @param size count of children
   */
  private void checkLong(List<ASN1> childList, int size)
  {
    if (!Arrays.equals(ECPublicKeyPath.PRIME_MODULUS.getTag().toByteArray(),
                       childList.get(IDX_FULL_PRIME_MODULUS).getDTagBytes()))
    {
      throw new IllegalArgumentException(ERROR_MESSAGE_NO_EC_PUBLIC_KEY);
    }
    if (!Arrays.equals(ECPublicKeyPath.COEFFICIENT_A.getTag().toByteArray(),
                       childList.get(IDX_FULL_COEFFICIENT_A).getDTagBytes()))
    {
      throw new IllegalArgumentException(ERROR_MESSAGE_NO_EC_PUBLIC_KEY);
    }
    if (!Arrays.equals(ECPublicKeyPath.COEFFICIENT_B.getTag().toByteArray(),
                       childList.get(IDX_FULL_COEFFICIENT_B).getDTagBytes()))
    {
      throw new IllegalArgumentException(ERROR_MESSAGE_NO_EC_PUBLIC_KEY);
    }
    if (!Arrays.equals(ECPublicKeyPath.BASE_POINT_G.getTag().toByteArray(),
                       childList.get(IDX_FULL_BASE_POINT).getDTagBytes()))
    {
      throw new IllegalArgumentException(ERROR_MESSAGE_NO_EC_PUBLIC_KEY);
    }
    if (!Arrays.equals(ECPublicKeyPath.ORDER_OF_BASE_POINT_R.getTag().toByteArray(),
                       childList.get(IDX_FULL_ORDER_BASE_POINT).getDTagBytes()))
    {
      throw new IllegalArgumentException(ERROR_MESSAGE_NO_EC_PUBLIC_KEY);
    }
    if (!Arrays.equals(ECPublicKeyPath.PUBLIC_POINT_Y.getTag().toByteArray(),
                       childList.get(IDX_FULL_PUBLIC_POINT_Y).getDTagBytes()))
    {
      throw new IllegalArgumentException(ERROR_MESSAGE_NO_EC_PUBLIC_KEY);
    }
    if (size == 8
        && !Arrays.equals(ECPublicKeyPath.CO_FACTOR_F.getTag().toByteArray(),
                          childList.get(IDX_FULL_CO_FACTOR_F).getDTagBytes()))
    {
      throw new IllegalArgumentException(ERROR_MESSAGE_NO_EC_PUBLIC_KEY);
    }
  }

  /**
   * Checks short form of public key with public point and optional cofactor.
   * 
   * @param childList list of children
   * @param size count of children
   */
  private void checkShort(List<ASN1> childList, int size)
  {
    if (!Arrays.equals(ECPublicKeyPath.PUBLIC_POINT_Y.getTag().toByteArray(),
                       childList.get(IDX_SHORT_PUBLIC_POINT_Y).getDTagBytes()))
    {
      throw new IllegalArgumentException(ERROR_MESSAGE_NO_EC_PUBLIC_KEY);
    }
    if (size == 3
        && !Arrays.equals(ECPublicKeyPath.CO_FACTOR_F.getTag().toByteArray(),
                          childList.get(IDX_SHORT_CO_FACTOR_F).getDTagBytes()))
    {
      throw new IllegalArgumentException(ERROR_MESSAGE_NO_EC_PUBLIC_KEY);
    }
  }

  /** {@inheritDoc} */
  @Override
  public ASN1 getChildElementByPath(ASN1Path part) throws IOException
  {
    if (!ECPublicKeyPath.class.isInstance(part))
    {
      throw new IllegalArgumentException("only ECPublicKeyPath permitted");
    }
    return super.getChildElementByPath(part);
  }

  /** {@inheritDoc} */
  @Override
  public ASN1 decode(byte[] bytes) throws
    IOException
  {
    ECPublicKey key = new ECPublicKey(bytes);
    super.decode(key);
    check();
    return this;
  }

  /** {@inheritDoc} */
  @Override
  public ASN1 decode(ASN1 asn1)
  {
    super.decode(asn1);
    check();
    return this;
  }

  public OID getOID() throws IOException
  {
    return (OID)getChildElementByPath(ECPublicKeyPath.OID);
  }
}

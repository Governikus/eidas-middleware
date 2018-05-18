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

import de.governikus.eumw.poseidas.cardbase.asn1.ASN1Constants;
import de.governikus.eumw.poseidas.cardbase.asn1.ASN1Encoder;
import de.governikus.eumw.poseidas.cardbase.asn1.ASN1Path;
import de.governikus.eumw.poseidas.cardbase.asn1.OID;


/**
 * Path for child elements of an {@link ECPublicKey}.
 * 
 * @author Arne Stahlbock, ast@bos-bremen.de
 */
public final class ECPublicKeyPath extends ASN1Path
{

  /**
   * Constructor.
   * 
   * @param name name
   * @param tag tag byte of child element
   * @param index index of child element
   * @param parent optional parent path element
   * @param encoderClass Class of {@link ASN1Encoder} for creating ASN1. object with support convenience
   *          methods to access contents of ASN.1, <code>null</code> permitted, any real Class must possess an
   *          empty, accessible Constructor to create an instance, otherwise an
   *          {@link IllegalArgumentException} is thrown
   * @throws IllegalArgumentException if Class of {@link ASN1Encoder} does not possess an empty constructor
   *           for initialization
   * @see ASN1Path#ASN1Path(String, byte, int, ASN1Path, Class)
   */
  private ECPublicKeyPath(String name,
                          byte tag,
                          int index,
                          ECPublicKeyPath parent,
                          Class<? extends ASN1Encoder> encoderClass)
  {
    super(name, tag, index, parent, encoderClass);
  }

  /**
   * Constructor.
   * 
   * @param name name
   * @param tagByteString tag of child element as Hex-String
   * @param index index of child element
   * @param parent optional parent path element
   * @see ASN1Path#ASN1Path(String, String, int, ASN1Path)
   */
  private ECPublicKeyPath(String name, String tagByteString, int index, ECPublicKeyPath parent)
  {
    super(name, tagByteString, index, parent);
  }

  /**
   * Constructor.
   * 
   * @param name name
   * @param tagByteString tag of child element
   * @param index index of child element
   * @param parent optional parent path element
   * @see ASN1Path#ASN1Path(String, String, int, ASN1Path)
   */
  private ECPublicKeyPath(String name, byte[] tagByte, int index, ECPublicKeyPath parent)
  {
    super(name, tagByte, index, parent);
  }

  /**
   * Path to public key of certificate body.
   */
  static final ECPublicKeyPath EC_PUBLIC_KEY = new ECPublicKeyPath("PUBLIC_KEY",
                                                                   ASN1EidConstants.TAG_PUBLIC_KEY.toArray(),
                                                                   0,
                                                                          null);

  /**
   * Path to OID of public key.
   */
  static final ECPublicKeyPath OID = new ECPublicKeyPath("OID", ASN1Constants.UNIVERSAL_TAG_OID, 0,
                                                                EC_PUBLIC_KEY, OID.class);

  /**
   * Path to prime modulus (curve parameter) of public key.
   */
  public static final ECPublicKeyPath PRIME_MODULUS = new ECPublicKeyPath("PRIME_MODULUS", "81", 0,
                                                                          EC_PUBLIC_KEY);

  /**
   * Path to coefficient A (curve parameter) of public key.
   */
  public static final ECPublicKeyPath COEFFICIENT_A = new ECPublicKeyPath("COEFFICIENT_A", "82", 0,
                                                                          EC_PUBLIC_KEY);

  /**
   * Path to coefficient B (curve parameter) of public key.
   */
  public static final ECPublicKeyPath COEFFICIENT_B = new ECPublicKeyPath("COEFFICIENT_B", "83", 0,
                                                                          EC_PUBLIC_KEY);

  /**
   * Path to base point G (curve parameter) of public key.
   */
  public static final ECPublicKeyPath BASE_POINT_G = new ECPublicKeyPath("BASE_POINT_G", "84", 0,
                                                                         EC_PUBLIC_KEY);

  /**
   * Path to order of base point R (curve parameter) of public key.
   */
  public static final ECPublicKeyPath ORDER_OF_BASE_POINT_R = new ECPublicKeyPath("ORDER_OF_BASE_POINT_R",
                                                                                  "85", 0, EC_PUBLIC_KEY);

  /**
   * Path to public key point (represents public key of owner) of public key.
   */
  public static final ECPublicKeyPath PUBLIC_POINT_Y = new ECPublicKeyPath("PUBLIC_POINT_Y", "86", 0,
                                                                           EC_PUBLIC_KEY);

  /**
   * Path to cofactor (curve parameter) of public key.
   */
  public static final ECPublicKeyPath CO_FACTOR_F = new ECPublicKeyPath("CO_FACTOR_F", "87", 0, EC_PUBLIC_KEY);
}

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

import de.governikus.eumw.poseidas.cardbase.Filter;
import de.governikus.eumw.poseidas.cardbase.asn1.ASN1;
import de.governikus.eumw.poseidas.cardbase.asn1.ASN1Constants;
import de.governikus.eumw.poseidas.cardbase.asn1.ASN1Encoder;
import de.governikus.eumw.poseidas.cardbase.asn1.ASN1Path;
import de.governikus.eumw.poseidas.cardbase.asn1.FindElementByOIDChildFilter;
import de.governikus.eumw.poseidas.cardbase.asn1.OID;


/**
 * Path for child elements of an {@link ECCVCertificate}.
 * 
 * @see ECCVCertificate
 * @author Arne Stahlbock, ast@bos-bremen.de
 * @author Jens Wothe, jw@bos-bremen.de
 */
public class ECCVCPath extends ASN1Path
{

  /**
   * Constructor.
   * 
   * @param name name
   * @param tag tag byte of child element
   * @param filter filter of child element
   * @param parent optional parent path element
   * @param encoderClass Class of {@link ASN1Encoder} for creating ASN1. object with support convenience
   *          methods to access contents of ASN.1, <code>null</code> permitted, any real Class must possess an
   *          empty, accessible Constructor to create an instance, otherwise an
   *          {@link IllegalArgumentException} is thrown
   * @throws IllegalArgumentException if Class of {@link ASN1Encoder} does not possess an empty constructor
   *           for initialization
   * @see ASN1Path#ASN1Path(String, byte, Filter, ASN1Path, Class)
   */
  private ECCVCPath(String name,
                    byte tag,
                    Filter<ASN1> filter,
                    ECCVCPath parent,
                    Class<? extends ASN1Encoder> encoderClass)
  {
    super(name, tag, filter, parent, encoderClass);
  }

  /**
   * Constructor.
   * 
   * @param name name
   * @param tagByte tag of child element
   * @param filter filter of child element
   * @param parent optional parent path element
   * @see ASN1Path#ASN1Path(String, String, Filter, ASN1Path)
   */
  private ECCVCPath(String name, byte tagByte, Filter<ASN1> filter, ECCVCPath parent)
  {
    this(name, tagByte, filter, parent, null);
  }

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
  private ECCVCPath(String name,
                    byte tag,
                    int index,
                    ECCVCPath parent,
                    Class<? extends ASN1Encoder> encoderClass)
  {
    super(name, tag, index, parent, encoderClass);
  }

  /**
   * Constructor.
   * 
   * @param name name
   * @param tagBytes tag bytes of child element
   * @param index index of child element
   * @param parent optional parent path element
   * @param encoderClass Class of {@link ASN1Encoder} for creating ASN1. object with support convenience
   *          methods to access contents of ASN.1, <code>null</code> permitted, any real Class must possess an
   *          empty, accessible Constructor to create an instance, otherwise an
   *          {@link IllegalArgumentException} is thrown
   * @throws IllegalArgumentException if Class of {@link ASN1Encoder} does not possess an empty constructor
   *           for initialization
   * @see ASN1Path#ASN1Path(String, byte[], int, ASN1Path, Class)
   */
  private ECCVCPath(String name,
                    byte[] tagBytes,
                    int index,
                    ECCVCPath parent,
                    Class<? extends ASN1Encoder> encoderClass)
  {
    super(name, tagBytes, index, parent, encoderClass);
  }

  /**
   * Constructor.
   * 
   * @param name name
   * @param tagBytes tag bytes of child element
   * @param index index of child element
   * @param parent optional parent path element
   * @see ASN1Path#ASN1Path(String, byte[], int, ASN1Path)
   */
  private ECCVCPath(String name, byte[] tagBytes, int index, ECCVCPath parent)
  {
    super(name, tagBytes, index, parent);
  }

  /**
   * Constructor.
   * 
   * @param name name
   * @param tagByte tag of child element
   * @param index index of child element
   * @param parent optional parent path element
   * @see ASN1Path#ASN1Path(String, String, int, ASN1Path)
   */
  private ECCVCPath(String name, byte tagByte, int index, ECCVCPath parent)
  {
    this(name, tagByte, index, parent, null);
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
  private ECCVCPath(String name, String tagByteString, int index, ECCVCPath parent)
  {
    super(name, tagByteString, index, parent);
  }

  /**
   * Path to root of CVCertificate - see table C.1 at TC-03110, version 2.02.
   */
  static final ECCVCPath CV_CERTIFICATE = new ECCVCPath("CV_CERTIFICATE", "7f21", 0, null);

  /**
   * Path to certificate body of CVCertificate.
   */
  public static final ECCVCPath CV_CERTIFICATE_BODY = new ECCVCPath("CV_CERTIFICATE_BODY",
                                                                    ASN1EidConstants.TAG_CERTIFICATE_BODY.toArray(),
                                                                    0, CV_CERTIFICATE);

  /**
   * Path to profile identifier of certificate body.
   */
  static final ECCVCPath PROFILE_IDENTIFIER = new ECCVCPath("PROFILE_IDENTIFIER",
                                                            ASN1EidConstants.TAG_CERTIFICATE_PROFILE_IDENTIFIER.toArray(),
                                                            0, CV_CERTIFICATE_BODY);

  /**
   * Path to CA reference of certificate body.
   */
  public static final ECCVCPath CA_REFERENCE = new ECCVCPath("CA_REFERENCE",
                                                             ASN1EidConstants.TAG_CERTIFICATION_AUTHORITY_REFERENCE,
                                                             0, CV_CERTIFICATE_BODY);

  /**
   * Path to holder reference of certificate body.
   */
  public static final ECCVCPath HOLDER_REFERENCE = new ECCVCPath("HOLDER_REFERENCE",
                                                                 ASN1EidConstants.TAG_CERTIFICATE_HOLDER_REFERENCE.toArray(),
                                                                 0, CV_CERTIFICATE_BODY);

  /**
   * Path to holder authorization template of certificate body.
   */
  public static final ECCVCPath CERTIFICATE_HOLDER_AUTHORIZATION_TEMPLATE = new ECCVCPath("HOLDER_AUTH_TEMPLATE",
                                                                                          ASN1EidConstants.TAG_CERTIFICATE_HOLDER_AUTHORIZATION_TEMPLATE.toArray(),
                                                                                          0,
                                                                                          CV_CERTIFICATE_BODY,
                                                                                          CertificateHolderAuthorizationTemplate.class);

  /**
   * Path to effective date of certificate body.
   */
  public static final ECCVCPath EFFECTIVE_DATE = new ECCVCPath("EFFECTIVE_DATE",
                                                               ASN1EidConstants.TAG_CERTIFICATE_EFFECTIVE_DATE.toArray(),
                                                               0, CV_CERTIFICATE_BODY);

  /**
   * Path to expiration date of certificate body.
   */
  public static final ECCVCPath EXPIRATION_DATE = new ECCVCPath("EXPIRATION_DATE",
                                                                ASN1EidConstants.TAG_CERTIFICATE_EXPIRATION_DATE.toArray(),
                                                                0, CV_CERTIFICATE_BODY);

  /**
   * Path to public key of certificate body.
   */
  static final ECCVCPath PUBLIC_KEY = new ECCVCPath("PUBLIC_KEY", ASN1EidConstants.TAG_PUBLIC_KEY.toArray(),
                                                    0, CV_CERTIFICATE_BODY, ECPublicKey.class);

  /**
   * Path to OID of public key.
   */
  public static final ECCVCPath PUBLIC_KEY_OID = new ECCVCPath("OID", ASN1Constants.UNIVERSAL_TAG_OID, 0,
                                                               PUBLIC_KEY, OID.class);

  /**
   * Path to prime modulus (curve parameter) of public key.
   */
  public static final ECCVCPath PUBLIC_KEY_PRIME_MODULUS = new ECCVCPath("PUBLIC_KEY_PRIME_MODULUS", "81", 0,
                                                                         PUBLIC_KEY);

  /**
   * Path to coefficient A (curve parameter) of public key.
   */
  public static final ECCVCPath PUBLIC_KEY_COEFFICIENT_A = new ECCVCPath("PUBLIC_KEY_COEFFICIENT_A", "82", 0,
                                                                         PUBLIC_KEY);

  /**
   * Path to coefficient B (curve parameter) of public key.
   */
  public static final ECCVCPath PUBLIC_KEY_COEFFICIENT_B = new ECCVCPath("PUBLIC_KEY_COEFFICIENT_B", "83", 0,
                                                                         PUBLIC_KEY);

  /**
   * Path to base point G (curve parameter) of public key.
   */
  public static final ECCVCPath PUBLIC_KEY_BASE_POINT_G = new ECCVCPath("PUBLIC_KEY_BASE_POINT_G", "84", 0,
                                                                        PUBLIC_KEY);

  /**
   * Path to order of base point R (curve parameter) of public key.
   */
  public static final ECCVCPath PUBLIC_KEY_ORDER_OF_BASE_POINT_R = new ECCVCPath("PUBLIC_KEY_ORDER_OF_BASE_POINT_R",
                                                                                 "85", 0, PUBLIC_KEY);

  /**
   * Path to cofactor (curve parameter) of public key.
   */
  public static final ECCVCPath PUBLIC_KEY_CO_FACTOR_F = new ECCVCPath("PUBLIC_KEY_CO_FACTOR_F", "87", 0,
                                                                       PUBLIC_KEY);

  /**
   * Path to signature of certificate.
   */
  public static final ECCVCPath SIGNATURE = new ECCVCPath("SIGNATURE",
                                                          ASN1EidConstants.TAG_SIGNATURE.toArray(), 0,
                                                          CV_CERTIFICATE);

  /**
   * Path to certificate extensions of certificate body.
   */
  public static final ECCVCPath CERTIFICATE_EXTENSIONS = new ECCVCPath("BODY_CERTIFICATE_EXTENSIONS",
                                                                       ASN1EidConstants.TAG_CERTIFICATE_EXTENSIONS,
                                                                       0, CV_CERTIFICATE_BODY);

  /**
   * Constant of OID for certificate description content at certificate extensions.
   */
  private static final String OID_CERTIFICATE_DESCRIPTION = "0.4.0.127.0.7.3.1.3.1";

  /**
   * Constant of OID for terminal sector (RI) content at certificate extensions.
   */
  private static final String OID_TERMINAL_SECTOR_RI = "0.4.0.127.0.7.3.1.3.2";

  /**
   * Filter for certificate descriptions content at certificate extensions.
   */
  private static final Filter<ASN1> CERTIFICATE_DESCRIPTION_FILTER = new FindElementByOIDChildFilter(OID_CERTIFICATE_DESCRIPTION);

  /**
   * Filter for terminal sector (RI) content at certificate extensions.
   */
  private static final Filter<ASN1> TERMINAL_SECTOR_RI_FILTER = new FindElementByOIDChildFilter(OID_TERMINAL_SECTOR_RI);

  /**
   * Filter for eID Access content at certificate extensions.
   */
  private static final Filter<ASN1> EID_ACCESS_FILTER = new FindElementByOIDChildFilter(ATEidAccessConstants.OID_ACCESS_ROLE_AND_RIGHTS_AUTHENTICATION_TERMINAL_EID_ACCESS);

  /**
   * Filter for special functions content at certificate extensions.
   */
  private static final Filter<ASN1> SPECIAL_FUNCTION_FILTER = new FindElementByOIDChildFilter(ATSpecialConstants.OID_ACCESS_ROLE_AND_RIGHTS_AUTHENTICATION_TERMINAL_SPECIAL_FUNCTIONS);

  /**
   * Filter for specific attributes content at certificate extensions.
   */
  private static final Filter<ASN1> SPECIFIC_ATTRIBUTES_FILTER = new FindElementByOIDChildFilter(ATSpecificAttributesConstants.OID_ACCESS_ROLE_AND_RIGHTS_AUTHENTICATION_TERMINAL_SPECIFIC_ATTRIBUTES);

  /**
   * Path to certificate description as certificate discretionary data of certificate at certificate
   * extensions. extensions.
   */
  private static final ECCVCPath EXTENSIONS_DISCRETIONARY_DATA_CERTIFICATE_DESCRIPTION = new ECCVCPath("EXTENSIONS_DISCRETIONARY_DATA_CERTIFICATE_DESCRIPTIONS",
                                                                                                       ASN1EidConstants.TAG_DISCRETIONARY_DATA_TEMPLATE,
                                                                                                       ECCVCPath.CERTIFICATE_DESCRIPTION_FILTER,
                                                                                                       ECCVCPath.CERTIFICATE_EXTENSIONS);

  /**
   * Path to certificate description first hash as discretionary data as certificate discretionary data of
   * certificate at certificate extensions.
   */
  public static final ECCVCPath EXTENSIONS_DISCRETIONARY_DATA_CERTIFICATE_DESCRIPTION_HASH = new ECCVCPath("EXTENSIONS_DISCRETIONARY_DATA_CERTIFICATE_DESCRIPTION_HASH",
                                                                                                           "80",
                                                                                                           0,
                                                                                                           EXTENSIONS_DISCRETIONARY_DATA_CERTIFICATE_DESCRIPTION);

  /**
   * Path to terminal sector (RI) as discretionary data as certificate discretionary data of certificate at
   * certificate extensions.
   */
  private static final ECCVCPath EXTENSIONS_DISCRETIONARY_DATA_TERMINAL_SECTOR_RI = new ECCVCPath("EXTENSIONS_DISCRETIONARY_DATA_TERMINAL_SECTOR_RI",
                                                                                                  ASN1EidConstants.TAG_DISCRETIONARY_DATA_TEMPLATE,
                                                                                                  ECCVCPath.TERMINAL_SECTOR_RI_FILTER,
                                                                                                  ECCVCPath.CERTIFICATE_EXTENSIONS);

  /**
   * Path to terminal sector (RI) first hash as discretionary data as certificate discretionary data of
   * certificate at certificate extensions.
   */
  static final ECCVCPath EXTENSIONS_DISCRETIONARY_DATA_TERMINAL_SECTOR_RI_FIRST_HASH = new ECCVCPath("EXTENSIONS_DISCRETIONARY_DATA_TERMINAL_SECTOR_RI_FIRST_HASH",
                                                                                                     "80", 0,
                                                                                                     EXTENSIONS_DISCRETIONARY_DATA_TERMINAL_SECTOR_RI);

  /**
   * Path to terminal sector (RI) second hash as discretionary data as certificate discretionary data of
   * certificate at certificate extensions.
   */
  static final ECCVCPath EXTENSIONS_DISCRETIONARY_DATA_TERMINAL_SECTOR_RI_SECOND_HASH = new ECCVCPath("EXTENSIONS_DISCRETIONARY_DATA_TERMINAL_SECTOR_RI_SECOND_HASH",
                                                                                                      "81", 0,
                                                                                                      EXTENSIONS_DISCRETIONARY_DATA_TERMINAL_SECTOR_RI);

  /**
   * Path to eID Access matrix as certificate discretionary data.
   */
  static final ECCVCPath EXTENSIONS_DISCRETIONARY_DATA_EID_ACCESS = new ECCVCPath("EXTENSIONS_DISCRETIONARY_DATA_SPECIAL_FUNCTIONS",
                                                                                  ASN1EidConstants.TAG_DISCRETIONARY_DATA_TEMPLATE,
                                                                                  ECCVCPath.EID_ACCESS_FILTER,
                                                                                  ECCVCPath.CERTIFICATE_EXTENSIONS);

  /**
   * Path to special functions matrix as certificate discretionary data.
   */
  static final ECCVCPath EXTENSIONS_DISCRETIONARY_DATA_SPECIAL_FUNCTIONS = new ECCVCPath("EXTENSIONS_DISCRETIONARY_DATA_SPECIAL_FUNCTIONS",
                                                                                         ASN1EidConstants.TAG_DISCRETIONARY_DATA_TEMPLATE,
                                                                                         ECCVCPath.SPECIAL_FUNCTION_FILTER,
                                                                                         ECCVCPath.CERTIFICATE_EXTENSIONS);

  /**
   * Path to specific attributes matrix as certificate discretionary data.
   */
  static final ECCVCPath EXTENSIONS_DISCRETIONARY_DATA_SPECIFIC_ATTRIBUTES = new ECCVCPath("EXTENSIONS_DISCRETIONARY_DATA_SPECIFIC_ATTRIBUTES",
                                                                                           ASN1EidConstants.TAG_DISCRETIONARY_DATA_TEMPLATE,
                                                                                           ECCVCPath.SPECIFIC_ATTRIBUTES_FILTER,
                                                                                           ECCVCPath.CERTIFICATE_EXTENSIONS);
}

/*
 * Copyright (c) 2019 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardbase.asn1.npa;

import java.math.BigInteger;

import de.governikus.eumw.poseidas.cardbase.asn1.ASN1Constants;
import de.governikus.eumw.poseidas.cardbase.asn1.ASN1Encoder;
import de.governikus.eumw.poseidas.cardbase.asn1.ASN1Path;
import de.governikus.eumw.poseidas.cardbase.asn1.ASN1PathType;
import de.governikus.eumw.poseidas.cardbase.asn1.OID;


/**
 * Path for child elements of a {@link CertificateDescription}.
 *
 * @see CertificateDescription
 * @author Jens Wothe, jw@bos-bremen.de
 */
public class CertificateDescriptionPath extends ASN1Path
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
  private CertificateDescriptionPath(String name,
                                    byte tag,
                                    int index,
                                    CertificateDescriptionPath parent,
                                    Class<? extends ASN1Encoder> encoderClass)
  {
    super(name, tag, index, parent, encoderClass);
  }

  /**
   * Constructor.
   *
   * @param name name
   * @param tag tag of child element
   * @param index index of child element
   * @param parent optional parent path element
   * @param encoderClass Class of {@link ASN1Encoder} for creating ASN1. object with support convenience
   *          methods to access contents of ASN.1, <code>null</code> permitted, any real Class must possess an
   *          empty, accessible Constructor to create an instance, otherwise an
   *          {@link IllegalArgumentException} is thrown
   * @throws IllegalArgumentException if Class of {@link ASN1Encoder} does not possess an empty constructor
   *           for initialization
   * @see ASN1Path#ASN1Path(String, BigInteger, int, ASN1Path, Class, ASN1PathType)
   */
  private CertificateDescriptionPath(String name,
                                    BigInteger tag,
                                    int index,
                                    CertificateDescriptionPath parent,
                                    Class<? extends ASN1Encoder> encoderClass)
  {
    super(name, tag, index, parent, encoderClass, ASN1PathType.NO_INFORMATION);
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
  private CertificateDescriptionPath(String name,
                                    byte[] tagBytes,
                                    int index,
                                    CertificateDescriptionPath parent,
                                    Class<? extends ASN1Encoder> encoderClass)
  {
    super(name, tagBytes, index, parent, encoderClass);
  }

  /**
   * Constructor.
   *
   * @param name name
   * @param tagByteString tag of child element as Hex-String
   * @param index index of child element
   * @param parent optional parent path element
   * @param encoderClass Class of {@link ASN1Encoder} for creating ASN1. object with support convenience
   *          methods to access contents of ASN.1, <code>null</code> permitted, any real Class must possess an
   *          empty, accessible Constructor to create an instance, otherwise an
   *          {@link IllegalArgumentException} is thrown
   * @throws IllegalArgumentException if Class of {@link ASN1Encoder} does not possess an empty constructor
   *           for initialization
   * @see ASN1Path#ASN1Path(String, String, int, ASN1Path, Class)
   */
  private CertificateDescriptionPath(String name,
                                    String tagByteString,
                                    int index,
                                    CertificateDescriptionPath parent,
                                    Class<? extends ASN1Encoder> encoderClass)
  {
    super(name, tagByteString, index, parent, encoderClass);
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
  private CertificateDescriptionPath(String name, byte[] tagBytes, int index, CertificateDescriptionPath parent)
  {
    super(name, tagBytes, index, parent);
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
  private CertificateDescriptionPath(String name,
                                    String tagByteString,
                                    int index,
                                    CertificateDescriptionPath parent)
  {
    super(name, tagByteString, index, parent);
  }

  /**
   * Constructor.
   *
   * @param name name
   * @param tag tag of child element
   * @param index index of child element
   * @param parent optional parent path element
   * @throws IllegalArgumentException if Class of {@link ASN1Encoder} does not possess an empty constructor
   *           for initialization
   * @see ASN1Path#ASN1Path(String, BigInteger, int, ASN1Path)
   */
  private CertificateDescriptionPath(String name,
                                       BigInteger tag,
                                       int index,
                                       CertificateDescriptionPath parent)
  {
    super(name, tag, index, parent);
  }

  /**
   * Path to root of certificate description - see table C.3.1 at TC-03110, version 2.02.
   */
  static final CertificateDescriptionPath CERTIFICATE_DESCRIPTION = new CertificateDescriptionPath(
                                                                                                          "CERTIFICATE_DESCRIPTION",
                                                                                                          ASN1Constants.UNIVERSAL_TAG_SEQUENCE_CONSTRUCTED,
                                                                                                          0,
                                                                                                          null,
                                                                                                          null);

  /**
   * Path to description type.
   */
  static final CertificateDescriptionPath DESCRIPTION_TYPE = new CertificateDescriptionPath(
                                                                                                   "DESCRIPTION_TYPE",
                                                                                                   ASN1Constants.UNIVERSAL_TAG_OID,
                                                                                                   0,
                                                                                                   CERTIFICATE_DESCRIPTION,
                                                                                                   OID.class);

  /**
   * Path to issuer name part.
   */
  static final CertificateDescriptionPath ISSUER_NAME_PART = new CertificateDescriptionPath(
                                                                                                   "ISSUER_NAME_PART",
                                                                                                   "a1", 0,
                                                                                                   CERTIFICATE_DESCRIPTION);

  /**
   * Path to issuer name.
   */
  static final CertificateDescriptionPath ISSUER_NAME = new CertificateDescriptionPath(
                                                                                              "ISSUER_NAME",
                                                                                              ASN1Constants.UTF8_STRING,
                                                                                              0,
                                                                                              ISSUER_NAME_PART,
                                                                                              null);

  /**
   * Path to issuer URL part.
   */
  static final CertificateDescriptionPath ISSUER_URL_PART = new CertificateDescriptionPath(
                                                                                                  "ISSUER_URL_PART",
                                                                                                  "a2", 0,
                                                                                                  CERTIFICATE_DESCRIPTION);

  /**
   * Path to issuer URL.
   */
  static final CertificateDescriptionPath ISSUER_URL = new CertificateDescriptionPath(
                                                                                             "ISSUER_URL",
                                                                                             ASN1Constants.UNIVERSAL_19_PRINTABLE_STRING,
                                                                                             0,
                                                                                             ISSUER_URL_PART,
                                                                                             null);

  /**
   * Path to subject name part.
   */
  static final CertificateDescriptionPath SUBJECT_NAME_PART = new CertificateDescriptionPath(
                                                                                                    "SUBJECT_NAME_PART",
                                                                                                    "a3", 0,
                                                                                                    CERTIFICATE_DESCRIPTION);

  /**
   * Path to subject name.
   */
  static final CertificateDescriptionPath SUBJECT_NAME = new CertificateDescriptionPath(
                                                                                               "SUBJECT_NAME",
                                                                                               ASN1Constants.UTF8_STRING,
                                                                                               0,
                                                                                               SUBJECT_NAME_PART,
                                                                                               null);

  /**
   * Path to subject URL part.
   */
  static final CertificateDescriptionPath SUBJECT_URL_PART = new CertificateDescriptionPath(
                                                                                                   "SUBJECT_URL_PART",
                                                                                                   "a4", 0,
                                                                                                   CERTIFICATE_DESCRIPTION);

  /**
   * Path to subject URL.
   */
  static final CertificateDescriptionPath SUBJECT_URL = new CertificateDescriptionPath(
                                                                                              "SUBJECT_URL",
                                                                                              ASN1Constants.UNIVERSAL_19_PRINTABLE_STRING,
                                                                                              0,
                                                                                              SUBJECT_URL_PART,
                                                                                              null);

  /**
   * Path to terms of usage defined by any description type.
   */
  private static final CertificateDescriptionPath TERMS_OF_USAGE = new CertificateDescriptionPath(
                                                                                                 "TERMS_OF_USAGE",
                                                                                                 "a5", 0,
                                                                                                 CERTIFICATE_DESCRIPTION);

  /**
   * Path to terms of usage defined as plain text.
   */
  static final CertificateDescriptionPath TERMS_OF_USAGE_PLAIN_TEXT = new CertificateDescriptionPath(
                                                                                                            "PLAIN_TEXT_TERMS_OF_USAGE",
                                                                                                            ASN1Constants.UTF8_STRING,
                                                                                                            0,
                                                                                                            TERMS_OF_USAGE,
                                                                                                            null);

  /**
   * Path to terms of usage defined as html.
   */
  static final CertificateDescriptionPath TERMS_OF_USAGE_HTML = new CertificateDescriptionPath(
                                                                                                      "HTML_TERMS_OF_USAGE",
                                                                                                      ASN1Constants.UNIVERSAL_22_IA5_STRING,
                                                                                                      0,
                                                                                                      TERMS_OF_USAGE,
                                                                                                      null);

  /**
   * Path to terms of usage defined as pdf.
   */
  static final CertificateDescriptionPath TERMS_OF_USAGE_PDF = new CertificateDescriptionPath(
                                                                                                     "PDF_TERMS_OF_USAGE",
                                                                                                     ASN1Constants.UNIVERSAL_TAG_OCTET_STRING,
                                                                                                     0,
                                                                                                     TERMS_OF_USAGE,
                                                                                                     null);

  /**
   * Path to optional redirect URL part.
   */
  static final CertificateDescriptionPath REDIRECT_URL_PART = new CertificateDescriptionPath(
                                                                                                    "REDIRECT_URL_PART",
                                                                                                    "a6", 0,
                                                                                                    CERTIFICATE_DESCRIPTION);

  /**
   * Path to optional redirect URL.
   */
  public static final CertificateDescriptionPath REDIRECT_URL = new CertificateDescriptionPath(
                                                                                               "REDIRECT_URL",
                                                                                               ASN1Constants.UNIVERSAL_19_PRINTABLE_STRING,
                                                                                               0,
                                                                                               REDIRECT_URL_PART,
                                                                                               null);

  /**
   * Path to optional comm certificates part.
   */
  static final CertificateDescriptionPath COMM_CERTIFICATES_PART = new CertificateDescriptionPath(
                                                                                                         "COMM_CERTIFICATES_PART",
                                                                                                         "a7",
                                                                                                         0,
                                                                                                         CERTIFICATE_DESCRIPTION);

  /**
   * Path to optional comm certificates.
   */
  public static final CertificateDescriptionPath COMM_CERTIFICATES = new CertificateDescriptionPath(
                                                                                                    "COMM_CERTIFICATES",
                                                                                                    "31",
                                                                                                    0,
                                                                                                    COMM_CERTIFICATES_PART,
                                                                                                    null);
}

/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardserver.certrequest;

import de.governikus.eumw.poseidas.cardbase.asn1.ASN1Constants;
import de.governikus.eumw.poseidas.cardbase.asn1.ASN1Encoder;
import de.governikus.eumw.poseidas.cardbase.asn1.ASN1Path;
import de.governikus.eumw.poseidas.cardbase.asn1.OID;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.ASN1EidConstants;


/**
 * Path for child elements of an {@link CertificateRequest}.
 *
 * @see CertificateRequest
 * @author Arne Stahlbock, ast@bos-bremen.de
 * @author Jens Wothe, jw@bos-bremen.de
 */
public class CertificateRequestPath extends ASN1Path
{

  /**
   * Constructor.
   *
   * @param name name
   * @param tagBytes tag bytes of child element
   * @param index index of child element
   * @param parent optional parent path element
   * @param encoderClass Class of {@link ASN1Encoder} for creating ASN1. object with support convenience methods to
   *          access contents of ASN.1, <code>null</code> permitted, any real Class must possess an empty, accessible
   *          Constructor to create an instance, otherwise an {@link IllegalArgumentException} is thrown
   * @throws IllegalArgumentException if Class of {@link ASN1Encoder} does not possess an empty constructor for
   *           initialization
   * @see ASN1Path#ASN1Path(String, byte, int, ASN1Path, Class)
   */
  private CertificateRequestPath(String name,
                                 byte tag,
                                 int index,
                                 ASN1Path parent,
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
   * @throws IllegalArgumentException if Class of {@link ASN1Encoder} does not possess an empty constructor for
   *           initialization
   * @see ASN1Path#ASN1Path(String, byte, int, ASN1Path, Class)
   */
  private CertificateRequestPath(String name, byte tag, int index, ASN1Path parent)
  {
    this(name, tag, index, parent, null);
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
  private CertificateRequestPath(String name, byte[] tagBytes, int index, ASN1Path parent)
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
  private CertificateRequestPath(String name, String tagByteString, int index, ASN1Path parent)
  {
    super(name, tagByteString, index, parent);
  }

  /**
   * Path to root of certificate request - authentication - see table D.1 at TC-03110, version 2.02.
   */
  static final CertificateRequestPath AUTHENTICATION = new CertificateRequestPath("CERTIFICATE_REQUEST", "67", 0, null);

  /**
   * Path to CVCertificate of request.
   */
  static final CertificateRequestPath CV_CERTIFICATE = new CertificateRequestPath("CV_CERTIFICATE",
                                                                                  ASN1EidConstants.TAG_CV_CERTIFICATE.toArray(),
                                                                                  0, AUTHENTICATION);

  /**
   * Path to certificate body of CVCertificate.
   */
  public static final CertificateRequestPath CV_CERTIFICATE_BODY = new CertificateRequestPath("CV_CERTIFICATE_BODY",
                                                                                              ASN1EidConstants.TAG_CERTIFICATE_BODY.toArray(),
                                                                                              0, CV_CERTIFICATE);

  /**
   * Path to CA reference of certificate body.
   */
  static final CertificateRequestPath CA_REFERENCE = new CertificateRequestPath("CA_REFERENCE",
                                                                                ASN1EidConstants.TAG_CERTIFICATION_AUTHORITY_REFERENCE,
                                                                                0, CV_CERTIFICATE_BODY);

  /**
   * Path to holder reference of certificate body.
   */
  public static final CertificateRequestPath HOLDER_REFERENCE = new CertificateRequestPath("HOLDER_REFERENCE",
                                                                                           ASN1EidConstants.TAG_CERTIFICATE_HOLDER_REFERENCE.toArray(),
                                                                                           0, CV_CERTIFICATE_BODY);

  /**
   * Path to public key of certificate body.
   */
  public static final CertificateRequestPath PUBLIC_KEY = new CertificateRequestPath("PUBLIC_KEY",
                                                                                     ASN1EidConstants.TAG_PUBLIC_KEY.toArray(),
                                                                                     0, CV_CERTIFICATE_BODY);

  /**
   * Path to signature of certificate (inner signature).
   */
  static final CertificateRequestPath SIGNATURE = new CertificateRequestPath("SIGNATURE",
                                                                             ASN1EidConstants.TAG_SIGNATURE.toArray(),
                                                                             0, CV_CERTIFICATE);

  /**
   * Path to certificate extensions of certificate body.
   */
  static final CertificateRequestPath CERTIFICATE_EXTENSIONS = new CertificateRequestPath("BODY_CERTIFICATE_EXTENSIONS",
                                                                                          ASN1EidConstants.TAG_CERTIFICATE_EXTENSIONS,
                                                                                          0, CV_CERTIFICATE_BODY);

  /**
   * Path to first certificate discretionary data (public key or certificate description) of certificate extensions.
   */
  static final CertificateRequestPath EXTENSIONS_DISCRETIONARY_DATA_FIRST = new CertificateRequestPath("EXTENSIONS_DISCRETIONARY_DATA_FIRST",
                                                                                                       ASN1EidConstants.TAG_DISCRETIONARY_DATA_TEMPLATE,
                                                                                                       0,
                                                                                                       CERTIFICATE_EXTENSIONS);

  /**
   * Path to first extension OID of certificate (public key or discretionary data - certificate description).
   */
  static final CertificateRequestPath DISCRETIONARY_DATA_FIRST_OID = new CertificateRequestPath("DISCRETIONARY_DATA_FIRST_OID",
                                                                                                ASN1Constants.UNIVERSAL_TAG_OID,
                                                                                                0,
                                                                                                EXTENSIONS_DISCRETIONARY_DATA_FIRST,
                                                                                                OID.class);

  /**
   * Path to first hash of certificate (public key or discretionary data - certificate description).
   */
  static final CertificateRequestPath DISCRETIONARY_DATA_FIRST_HASH = new CertificateRequestPath("DISCRETIONARY_DATA_FIRST_HASH",
                                                                                                 "80", 0,
                                                                                                 EXTENSIONS_DISCRETIONARY_DATA_FIRST);

  /**
   * Path to second certificate discretionary data (public key or certificate description) of certificate extensions.
   */
  static final CertificateRequestPath EXTENSIONS_DISCRETIONARY_DATA_SECOND = new CertificateRequestPath("EXTENSIONS_DISCRETIONARY_DATA_SECOND",
                                                                                                        ASN1EidConstants.TAG_DISCRETIONARY_DATA_TEMPLATE,
                                                                                                        1,
                                                                                                        CERTIFICATE_EXTENSIONS);

  /**
   * Path to second extension OID of certificate (public key or discretionary data - certificate description).
   */
  static final CertificateRequestPath DISCRETIONARY_DATA_SECOND_OID = new CertificateRequestPath("DISCRETIONARY_DATA_SECOND_OID",
                                                                                                 ASN1Constants.UNIVERSAL_TAG_OID,
                                                                                                 0,
                                                                                                 EXTENSIONS_DISCRETIONARY_DATA_SECOND,
                                                                                                 OID.class);

  /**
   * Path to second hash of certificate (public key or discretionary data - certificate description).
   */
  static final CertificateRequestPath DISCRETIONARY_DATA_SECOND_HASH = new CertificateRequestPath("DISCRETIONARY_DATA_SECOND_HASH",
                                                                                                  "80", 0,
                                                                                                  EXTENSIONS_DISCRETIONARY_DATA_SECOND);

  /**
   * Path to CA reference of request (conditional).
   */
  static final CertificateRequestPath OUTER_CA_REFERENCE = new CertificateRequestPath("OUTER_CA_REFERENCE",
                                                                                      ASN1EidConstants.TAG_CERTIFICATION_AUTHORITY_REFERENCE,
                                                                                      0, AUTHENTICATION);

  /**
   * Path to signature of request (conditional).
   */
  static final CertificateRequestPath OUTER_SIGNATURE = new CertificateRequestPath("OUTER_SIGNATURE",
                                                                                   ASN1EidConstants.TAG_SIGNATURE.toArray(),
                                                                                   0, AUTHENTICATION);

}

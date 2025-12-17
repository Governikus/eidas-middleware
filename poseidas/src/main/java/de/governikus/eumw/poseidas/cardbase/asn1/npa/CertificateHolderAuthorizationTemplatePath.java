/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardbase.asn1.npa;

import de.governikus.eumw.poseidas.cardbase.asn1.ASN1Constants;
import de.governikus.eumw.poseidas.cardbase.asn1.ASN1Encoder;
import de.governikus.eumw.poseidas.cardbase.asn1.ASN1Path;
import de.governikus.eumw.poseidas.cardbase.asn1.OID;


/**
 * Path for child elements of an {@link CertificateHolderAuthorizationTemplate}.
 *
 * @author Arne Stahlbock, ast@bos-bremen.de
 * @author Jens Wothe, jw@bos-bremen.de
 */
public class CertificateHolderAuthorizationTemplatePath extends ASN1Path
{

  /**
   * Constructor.
   *
   * @param name name
   * @param tag tag byte of child element
   * @param index index of child element
   * @param parent optional parent path element
   * @param encoderClass Class of {@link ASN1Encoder} for creating ASN1. object with support convenience methods to
   *          access contents of ASN.1, <code>null</code> permitted, any real Class must possess an empty, accessible
   *          Constructor to create an instance, otherwise an {@link IllegalArgumentException} is thrown
   * @throws IllegalArgumentException if Class of {@link ASN1Encoder} does not possess an empty constructor for
   *           initialization
   * @see ASN1Path#ASN1Path(String, byte, int, ASN1Path, Class)
   */
  private CertificateHolderAuthorizationTemplatePath(String name,
                                                     byte tag,
                                                     int index,
                                                     CertificateHolderAuthorizationTemplatePath parent,
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
   * @param encoderClass Class of {@link ASN1Encoder} for creating ASN1. object with support convenience methods to
   *          access contents of ASN.1, <code>null</code> permitted, any real Class must possess an empty, accessible
   *          Constructor to create an instance, otherwise an {@link IllegalArgumentException} is thrown
   * @throws IllegalArgumentException if Class of {@link ASN1Encoder} does not possess an empty constructor for
   *           initialization
   * @see ASN1Path#ASN1Path(String, byte[], int, ASN1Path, Class)
   */
  private CertificateHolderAuthorizationTemplatePath(String name,
                                                     byte[] tagBytes,
                                                     int index,
                                                     CertificateHolderAuthorizationTemplatePath parent,
                                                     Class<? extends ASN1Encoder> encoderClass)
  {
    super(name, tagBytes, index, parent, encoderClass);
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
  private CertificateHolderAuthorizationTemplatePath(String name,
                                                     byte tagByte,
                                                     int index,
                                                     CertificateHolderAuthorizationTemplatePath parent)
  {
    this(name, tagByte, index, parent, null);
  }


  /**
   * Path to holder authorization template of certificate body.
   */
  static final CertificateHolderAuthorizationTemplatePath CERTIFICATE_HOLDER_AUTHORIZATION_TEMPLATE = new CertificateHolderAuthorizationTemplatePath("HOLDER_AUTH_TEMPLATE",
                                                                                                                                                     ASN1EidConstants.TAG_CERTIFICATE_HOLDER_AUTHORIZATION_TEMPLATE.toArray(),
                                                                                                                                                     0,
                                                                                                                                                     null,
                                                                                                                                                     CertificateHolderAuthorizationTemplate.class);

  /**
   * Path to OID of holder authorization template.
   */
  static final CertificateHolderAuthorizationTemplatePath HAT_OID = new CertificateHolderAuthorizationTemplatePath("HAT_OID",
                                                                                                                   ASN1Constants.UNIVERSAL_TAG_OID,
                                                                                                                   0,
                                                                                                                   CERTIFICATE_HOLDER_AUTHORIZATION_TEMPLATE,
                                                                                                                   OID.class);

  /**
   * Path to role and access rights of holder authorization template.
   */
  static final CertificateHolderAuthorizationTemplatePath HAT_ACCESS_ROLE_AND_RIGHTS = new CertificateHolderAuthorizationTemplatePath("HAT_ACCESS_ROLE_AND_RIGHTS",
                                                                                                                                      ASN1EidConstants.TAG_DISCRETIONARY_DATA,
                                                                                                                                      0,
                                                                                                                                      CERTIFICATE_HOLDER_AUTHORIZATION_TEMPLATE);
}

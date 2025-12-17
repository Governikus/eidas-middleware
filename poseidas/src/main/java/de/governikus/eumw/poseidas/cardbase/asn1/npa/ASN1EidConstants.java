/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardbase.asn1.npa;

import de.governikus.eumw.poseidas.cardbase.ImmutableByteArray;


public final class ASN1EidConstants
{

  /**
   * Tag for certification authority reference: <code>0x42</code>.
   */
  public static final byte TAG_CERTIFICATION_AUTHORITY_REFERENCE = 0x42;

  /**
   * Tag for discretionary data: <code>0x53</code>.
   */
  public static final byte TAG_DISCRETIONARY_DATA = 0x53;

  /**
   * Tag for certificate holder reference: <code>0x5f20</code>.
   */
  public static final ImmutableByteArray TAG_CERTIFICATE_HOLDER_REFERENCE = ImmutableByteArray.of(new byte[]{0x5f,
                                                                                                             0x20});

  /**
   * Tag for certificate expiration date: <code>0x5f24</code>.
   */
  static final ImmutableByteArray TAG_CERTIFICATE_EXPIRATION_DATE = ImmutableByteArray.of(new byte[]{0x5f, 0x24});

  /**
   * Tag for certificate effective date: <code>0x5f25</code>.
   */
  static final ImmutableByteArray TAG_CERTIFICATE_EFFECTIVE_DATE = ImmutableByteArray.of(new byte[]{0x5f, 0x25});

  /**
   * Tag for certificate profile identifier: <code>0x5f29</code>.
   */
  static final ImmutableByteArray TAG_CERTIFICATE_PROFILE_IDENTIFIER = ImmutableByteArray.of(new byte[]{0x5f, 0x29});

  /**
   * Tag for certificate signature: <code>0x5f37</code>.
   */
  public static final ImmutableByteArray TAG_SIGNATURE = ImmutableByteArray.of(new byte[]{0x5f, 0x37});

  /**
   * Tag for certificate extensions: <code>0x65</code>.
   */
  public static final byte TAG_CERTIFICATE_EXTENSIONS = 0x65;

  /**
   * Tag for discretionary data template: <code>0x73</code>.
   */
  public static final byte TAG_DISCRETIONARY_DATA_TEMPLATE = 0x73;

  /**
   * Tag for CV certificate: <code>0x7f21</code>.
   */
  public static final ImmutableByteArray TAG_CV_CERTIFICATE = ImmutableByteArray.of(new byte[]{0x7f, 0x21});

  /**
   * Tag for public key: <code>0x7f49</code>.
   */
  public static final ImmutableByteArray TAG_PUBLIC_KEY = ImmutableByteArray.of(new byte[]{0x7f, 0x49});

  /**
   * Tag for certificate holder authorization template: <code>0x7f4c</code>.
   */
  static final ImmutableByteArray TAG_CERTIFICATE_HOLDER_AUTHORIZATION_TEMPLATE = ImmutableByteArray.of(new byte[]{0x7f,
                                                                                                                   0x4c});

  /**
   * Tag for certificate body: <code>0x7f4e</code>.
   */
  public static final ImmutableByteArray TAG_CERTIFICATE_BODY = ImmutableByteArray.of(new byte[]{0x7f, 0x4e});

  private ASN1EidConstants()
  {}
}

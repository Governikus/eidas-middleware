/*
 * Copyright (c) 2019 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardbase.asn1;

import java.io.IOException;


/**
 * Implementation of ASN.1 Encoder for {@link ASN1Path}.
 * <p>
 * Notice: an encodable supports convenience methods related to ASN.1 object for access of contents.
 * </p>
 *
 * @author Jens Wothe, jw@bos-bremen.de
 */
public interface ASN1Encoder
{

  /**
   * Decodes/Initializes ASN.1 object from bytes.
   *
   * @param bytes bytes of ASN.1, <code>null</code> or empty array not permitted
   * @return ASN.1 object
   * @throws IllegalArgumentException if bytes <code>null</code> or empty
   * @throws IOException if processing bytes fails, some decoding uses {@link ASN1#ASN1(byte[])}
   * @throws IllegalStateException if changing disabled
   * @throws UnsupportedOperationException if decoding from bytes not supported
   */
  public ASN1 decode(byte[] bytes) throws IOException;

  /**
   * Decodes/Initializes ASN.1 object from ASN.1 object.
   *
   * @param asn1 ASN.1 object, <code>null</code> not permitted
   * @return ASN.1 object
   * @throws IllegalArgumentException if ASN.1 object <code>null</code> or incompatible ASN.1 object
   * @throws IllegalStateException if changing disabled
   */
  public ASN1 decode(ASN1 asn1);

}

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

import de.governikus.eumw.poseidas.cardbase.asn1.ASN1;


/**
 * Interface for information identified by one or more bits.
 *
 * @author Jens Wothe, jw@bos-bremen.de
 */
public interface BitIdentifier
{

  /**
   * Gets index of significant byte.
   *
   * @return the byteIndex
   */
  public abstract int getByteIndex();

  /**
   * Gets mask of set bits.
   *
   * @return the bitMask
   */
  public abstract byte getBitMask();

  /**
   * Gets name of information identified.
   *
   * @return the name
   */
  public abstract String getName();

  /**
   * Checks value of ASN.1 indicates information identified by this instance.
   *
   * @param asn1 ASN.1 object
   * @return <code>true</code>, if significant bits set at significant byte, <code>false</code> otherwise
   */
  public abstract boolean accept(ASN1 asn1);

  /**
   * Checks byte[]-array indicates information identified by this instance.
   *
   * @param bytes bytes of an ASN.1 object or just simple bytes to check
   * @return <code>true</code>, if significant bits set at significant byte, <code>false</code> otherwise
   */
  public abstract boolean accept(byte[] bytes);

  /**
   * Gets mask of significant bits at byte.
   *
   * @return the byteMask
   */
  public byte getByteMask();

}

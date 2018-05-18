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

import de.governikus.eumw.poseidas.cardbase.AssertUtil;
import de.governikus.eumw.poseidas.cardbase.asn1.ASN1;


/**
 * Implementation for information identified by one or more bit.
 * 
 * @author Jens Wothe, jw@bos-bremen.de
 */
public class BitIdentifierImpl implements BitIdentifier
{

  // index of significant byte
  private int byteIndex = -1;

  /**
   * byte mask of significant bits at significant byte
   */
  private byte byteMask = (byte)0xff;

  // bit mask expected to be set at significant byte after AND with byte mask
  private byte bitMask = (byte)0xff;

  // name of information
  private String name = null;

  /**
   * Constructor.
   * 
   * @param name name of information, <code>null</code> or empty String not permitted
   * @param byteIndex index of significant byte, negative index not permitted
   * @param bitMask bit mask expected to be set at significant byte after AND with byte mask
   * @throws IllegalArgumentException if one argument value is not permitted
   */
  BitIdentifierImpl(String name, int byteIndex, byte bitMask)
  {
    this(name, byteIndex, bitMask, bitMask);
  }

  /**
   * Constructor.
   * 
   * @param name name of information, <code>null</code> or empty String not permitted
   * @param byteIndex index of significant byte, negative index not permitted
   * @param byteMask mask of significant bits at significant byte, bit mask must be a subset of byte mask
   * @param bitMask bit mask expected to be set at significant byte after AND with byte mask
   * @throws IllegalArgumentException if one argument value is not permitted
   */
  BitIdentifierImpl(String name, int byteIndex, byte byteMask, byte bitMask)
  {
    super();
    AssertUtil.notNullOrEmpty(name, "name");
    AssertUtil.zeroOrPositive(byteIndex, "index of significant byte");
    if ((byteMask & bitMask) != bitMask)
    {
      throw new IllegalArgumentException("illegal pair of byte mask and bit mask");
    }
    this.name = name;
    this.byteIndex = byteIndex;
    this.byteMask = byteMask;
    this.bitMask = bitMask;
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public int getByteIndex()
  {
    return this.byteIndex;
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public byte getBitMask()
  {
    return this.bitMask;
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public String getName()
  {
    return this.name;
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public byte getByteMask()
  {
    return this.byteMask;
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public boolean accept(ASN1 asn1)
  {
    if (asn1 == null)
    {
      return false;
    }
    return this.accept(asn1.getValue());
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public boolean accept(byte[] asn1ValueBytes)
  {
    if (asn1ValueBytes == null || asn1ValueBytes.length == 0 || asn1ValueBytes.length <= this.byteIndex)
    {
      return false;
    }
    return (asn1ValueBytes[this.byteIndex] & this.byteMask) == this.bitMask;
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public String toString()
  {
    return this.name;
  }

}

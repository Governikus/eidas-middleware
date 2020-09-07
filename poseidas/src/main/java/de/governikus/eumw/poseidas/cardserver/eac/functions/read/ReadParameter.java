/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardserver.eac.functions.read;

import de.governikus.eumw.poseidas.cardserver.eac.functions.FunctionParameter;


/**
 * Parmeter for reading.
 *
 * @author Jens Wothe, jw@bos-bremen.de
 */
public class ReadParameter implements FunctionParameter
{


  /**
   * Gets SFI (optional value).
   *
   * @return sfi
   */
  public final Byte getSfi()
  {
    return sfi;
  }


  /**
   * Gets read length.
   *
   * @return length
   */
  public final int getLength()
  {
    return length;
  }


  /**
   * Gets offset.
   *
   * @return the offset
   */
  public final int getOffset()
  {
    return offset;
  }

  /**
   * Constant for default read length.
   */
  private static final int DEFAULT_LENGTH = 0;

  /**
   * Constant for default offset.
   */
  private static final int DEFAULT_OFFSET = 0;

  /**
   * Constant for default SFI.
   */
  private static final Byte DEFAULT_SFI = null;

  private Byte sfi = DEFAULT_SFI;

  private int length = DEFAULT_LENGTH;

  private int offset = DEFAULT_OFFSET;

  /**
   * Constructor.
   */
  public ReadParameter()
  {
    this(DEFAULT_OFFSET, DEFAULT_LENGTH, DEFAULT_SFI);
  }

  /**
   * Constructor.
   *
   * @param offset offset for reading, default <code>0</code>, value greater equals <code>0</code> and less
   *          equals <code>32768</code> only permitted, when SFI given offset less equals <code>255</code>
   *          permitted only
   * @param length length for reading, default <code>0</code> for reading 256 bytes, value greater equals
   *          <code>0</code> and less equals than <code>65536</code> permitted only
   * @param sfi optional SFI
   * @throws IllegalArgumentException when arguments invalid
   */
  public ReadParameter(int offset, int length, Byte sfi)
  {
    super();
    if (offset < 0)
    {
      throw new IllegalArgumentException("only positive offset permitted");
    }

    if (sfi == null && offset > 32767)
    {
      throw new IllegalArgumentException("only offset less equals 32767 permitted");
    }
    if (sfi != null && offset > 255)
    {
      throw new IllegalArgumentException("only offset less equals 255 permitted (SFI set)");
    }
    if (length < 0)
    {
      throw new IllegalArgumentException("only positive length permitted");
    }
    if (length > 65536)
    {
      throw new IllegalArgumentException("only length less equals 65536 permitted");
    }
    this.offset = offset;
    this.length = length;
    this.sfi = sfi;
  }
}

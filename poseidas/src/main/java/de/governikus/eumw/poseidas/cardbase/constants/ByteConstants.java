/*
 * Copyright (c) 2019 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardbase.constants;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import de.governikus.eumw.poseidas.cardbase.ByteUtil;


/**
 * Constants for bits and bytes.
 *
 * @see ByteUtil
 * @author Jens Wothe, jw@bos-bremen.de
 */
public final class ByteConstants
{

  /**
   * Constant of zero byte: <code>0x00</code>.
   */
  public static final byte ZERO = (byte)0x00;

  /**
   * Constant of maximum bit index: <code>7</code>.
   */
  public static final int MAXIMUM_BIT_INDEX = 7;

  /**
   * Constant of minimum bit index: <code>0</code>.
   */
  public static final int MINIMUM_BIT_INDEX = 0;

  /**
   * Constant of index for eighth bit: <code>7</code>.
   *
   * @see #MASK_BIT8
   * @see #BYTE_MASK_BIT8
   */
  private static final int BIT_INDEX_8 = 7;

  /**
   * Constant of index for seventh bit: <code>6</code>.
   *
   * @see #MASK_BIT7
   * @see #BYTE_MASK_BIT7
   */
  private static final int BIT_INDEX_7 = 6;

  /**
   * Constant of index for sixth bit: <code>5</code>.
   *
   * @see #MASK_BIT6
   * @see #BYTE_MASK_BIT6
   */
  private static final int BIT_INDEX_6 = 5;

  /**
   * Constant of index for fifth bit: <code>4</code>.
   *
   * @see #MASK_BIT5
   * @see #BYTE_MASK_BIT5
   */
  private static final int BIT_INDEX_5 = 4;

  /**
   * Constant of index for fourth bit: <code>3</code>.
   *
   * @see #MASK_BIT4
   * @see #BYTE_MASK_BIT4
   */
  private static final int BIT_INDEX_4 = 3;

  /**
   * Constant of index for third bit: <code>2</code>.
   *
   * @see #MASK_BIT3
   * @see #BYTE_MASK_BIT3
   */
  private static final int BIT_INDEX_3 = 2;

  /**
   * Constant of index for second bit: <code>1</code>.
   *
   * @see #MASK_BIT2
   * @see #BYTE_MASK_BIT2
   */
  private static final int BIT_INDEX_2 = 1;

  /**
   * Constant of index for first bit: <code>0</code>.
   *
   * @see #MASK_BIT1
   * @see #BYTE_MASK_BIT1
   */
  private static final int BIT_INDEX_1 = 0;

  /**
   * Constant of bit mask for eighth bit: <code>0x80</code>.
   *
   * @see #BIT_INDEX_8
   * @see #BYTE_MASK_BIT8
   * @see Math#pow(double, double)
   */
  public static final byte MASK_BIT8 = (byte)(Math.pow(2, BIT_INDEX_8));

  /**
   * Constant of bit mask for seventh bit: <code>0x40</code>.
   *
   * @see #BIT_INDEX_7
   * @see #BYTE_MASK_BIT7
   * @see Math#pow(double, double)
   */
  private static final byte MASK_BIT7 = (byte)(Math.pow(2, BIT_INDEX_7));

  /**
   * Constant of bit mask for sixth bit: <code>0x20</code>.
   *
   * @see #BIT_INDEX_6
   * @see #BYTE_MASK_BIT6
   * @see Math#pow(double, double)
   */
  private static final byte MASK_BIT6 = (byte)(Math.pow(2, BIT_INDEX_6));

  /**
   * Constant of bit mask for fifth bit: <code>0x10</code>.
   *
   * @see #BIT_INDEX_5
   * @see #BYTE_MASK_BIT5
   * @see Math#pow(double, double)
   */
  private static final byte MASK_BIT5 = (byte)(Math.pow(2, BIT_INDEX_5));

  /**
   * Constant of bit mask for fourth bit: <code>0x08</code>.
   *
   * @see #BIT_INDEX_4
   * @see #BYTE_MASK_BIT4
   * @see Math#pow(double, double)
   */
  private static final byte MASK_BIT4 = (byte)(Math.pow(2, BIT_INDEX_4));

  /**
   * Constant of bit mask for third bit: <code>0x04</code>.
   *
   * @see #BIT_INDEX_3
   * @see #BYTE_MASK_BIT3
   * @see Math#pow(double, double)
   */
  private static final byte MASK_BIT3 = (byte)(Math.pow(2, BIT_INDEX_3));

  /**
   * Constant of bit mask for second bit: <code>0x02</code>.
   *
   * @see #BIT_INDEX_2
   * @see #BYTE_MASK_BIT2
   * @see Math#pow(double, double)
   */
  private static final byte MASK_BIT2 = (byte)(Math.pow(2, BIT_INDEX_2));

  /**
   * Constant of bit mask for first bit: <code>0x01</code>. see
   *
   * @see #BIT_INDEX_1
   * @see #BYTE_MASK_BIT1
   * @see Math#pow(double, double)
   */
  private static final byte MASK_BIT1 = (byte)(Math.pow(2, BIT_INDEX_1));

  /**
   * Constant of bit mask for eighth bit.
   *
   * @see #MASK_BIT8
   * @see #BIT_INDEX_MASK_LIST
   */
  private static final Byte BYTE_MASK_BIT8 = Byte.valueOf(MASK_BIT8);

  /**
   * Constant of bit mask for seventh bit.
   *
   * @see #MASK_BIT7
   * @see #BIT_INDEX_MASK_LIST
   */
  private static final Byte BYTE_MASK_BIT7 = Byte.valueOf(MASK_BIT7);

  /**
   * Constant of bit mask for sixth bit.
   *
   * @see #MASK_BIT6
   * @see #BIT_INDEX_MASK_LIST
   */
  private static final Byte BYTE_MASK_BIT6 = Byte.valueOf(MASK_BIT6);

  /**
   * Constant of bit mask for fifth bit.
   *
   * @see #MASK_BIT5
   * @see #BIT_INDEX_MASK_LIST
   */
  private static final Byte BYTE_MASK_BIT5 = Byte.valueOf(MASK_BIT5);

  /**
   * Constant of bit mask for fourth bit.
   *
   * @see #MASK_BIT4
   * @see #BIT_INDEX_MASK_LIST
   */
  private static final Byte BYTE_MASK_BIT4 = Byte.valueOf(MASK_BIT4);

  /**
   * Constant of bit mask for third bit.
   *
   * @see #MASK_BIT3
   * @see #BIT_INDEX_MASK_LIST
   */
  private static final Byte BYTE_MASK_BIT3 = Byte.valueOf(MASK_BIT3);

  /**
   * Constant of bit mask for second bit.
   *
   * @see #MASK_BIT2
   * @see #BIT_INDEX_MASK_LIST
   */
  private static final Byte BYTE_MASK_BIT2 = Byte.valueOf(MASK_BIT2);

  /**
   * Constant of bit mask for first bit.
   *
   * @see #MASK_BIT1
   * @see #BIT_INDEX_MASK_LIST
   */
  private static final Byte BYTE_MASK_BIT1 = Byte.valueOf(MASK_BIT1);

  /**
   * Constant list of bit mask in ascending order - accessing with bit index delivers related bit mask.
   */
  public static final List<Byte> BIT_INDEX_MASK_LIST = Collections.unmodifiableList(Arrays.asList(BYTE_MASK_BIT1,
                                                                                                  BYTE_MASK_BIT2,
                                                                                                  BYTE_MASK_BIT3,
                                                                                                  BYTE_MASK_BIT4,
                                                                                                  BYTE_MASK_BIT5,
                                                                                                  BYTE_MASK_BIT6,
                                                                                                  BYTE_MASK_BIT7,
                                                                                                  BYTE_MASK_BIT8));

  /**
   * Constructor.
   */
  private ByteConstants()
  {
    super();
  }

}

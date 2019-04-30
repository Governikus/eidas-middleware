/*
 * Copyright (c) 2019 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardbase;

import java.math.BigInteger;


/**
 * Interface of informations about number instances.
 *
 * @param <T>
 * @author Jens Wothe, jw@bos-bremen.de
 */
public interface NumInfo<T extends Number & Comparable<T>>
{

  /**
   * Constant representing zero:<code>0</code>.
   *
   * @see #getZero()
   * @see #ZERO_BYTE
   * @see #ZERO_SHORT
   * @see #ZERO_INTEGER
   * @see #ZERO_LONG
   * @see #ZERO_BIGINTEGER
   * @see #ZERO_FLOAT
   * @see #ZERO_DOUBLE
   */
  public static final int UNKNOWN_ZERO = 0;

  /**
   * Constant representing zero byte: <code>0x00</code>.
   *
   * @see #UNKNOWN_ZERO
   * @see #ZERO_SHORT
   * @see #ZERO_INTEGER
   * @see #ZERO_LONG
   * @see #ZERO_BIGINTEGER
   * @see #ZERO_FLOAT
   * @see #ZERO_DOUBLE
   */
  public static final Byte ZERO_BYTE = Byte.valueOf((byte)UNKNOWN_ZERO);

  /**
   * Constant representing zero short: <code>0</code>.
   *
   * @see #UNKNOWN_ZERO
   * @see #ZERO_BYTE
   * @see #ZERO_INTEGER
   * @see #ZERO_LONG
   * @see #ZERO_BIGINTEGER
   * @see #ZERO_FLOAT
   * @see #ZERO_DOUBLE
   */
  public static final Short ZERO_SHORT = Short.valueOf((short)UNKNOWN_ZERO);

  /**
   * Constant representing zero integer: <code>0</code>.
   *
   * @see #UNKNOWN_ZERO
   * @see #ZERO_BYTE
   * @see #ZERO_SHORT
   * @see #ZERO_LONG
   * @see #ZERO_BIGINTEGER
   * @see #ZERO_FLOAT
   * @see #ZERO_DOUBLE
   */
  public static final Integer ZERO_INTEGER = Integer.valueOf(UNKNOWN_ZERO);

  /**
   * Constant representing zero long: <code>0</code>.
   *
   * @see #UNKNOWN_ZERO
   * @see #ZERO_BYTE
   * @see #ZERO_SHORT
   * @see #ZERO_INTEGER
   * @see #ZERO_BIGINTEGER
   * @see #ZERO_FLOAT
   * @see #ZERO_DOUBLE
   */
  public static final Long ZERO_LONG = Long.valueOf(UNKNOWN_ZERO);

  /**
   * Constant representing zero BigInteger: <code>0</code>.
   *
   * @see BigInteger#ZERO
   * @see #ZERO_BYTE
   * @see #ZERO_SHORT
   * @see #ZERO_INTEGER
   * @see #ZERO_LONG
   * @see #ZERO_FLOAT
   * @see #ZERO_DOUBLE
   */
  public static final BigInteger ZERO_BIGINTEGER = BigInteger.ZERO;

  /**
   * Constant representing zero float: <code>0.0</code>.
   *
   * @see #UNKNOWN_ZERO
   * @see #ZERO_BYTE
   * @see #ZERO_SHORT
   * @see #ZERO_INTEGER
   * @see #ZERO_LONG
   * @see #ZERO_BIGINTEGER
   * @see #ZERO_DOUBLE
   */
  public static final Float ZERO_FLOAT = Float.valueOf(UNKNOWN_ZERO);

  /**
   * Constant representing zero double: <code>0.0</code>.
   *
   * @see #UNKNOWN_ZERO
   * @see #ZERO_BYTE
   * @see #ZERO_SHORT
   * @see #ZERO_INTEGER
   * @see #ZERO_LONG
   * @see #ZERO_BIGINTEGER
   * @see #ZERO_FLOAT
   */
  public static final Double ZERO_DOUBLE = Double.valueOf(UNKNOWN_ZERO);

  /**
   * Constant indicating size unknown.
   *
   * @see #getSize(Number)
   */
  public static final int UNKNOWN_SIZE = 0;

  /**
   * Constant representing unknown infinity value (general, for all numeric types no explicit positive or
   * negative infinity value is defined): <code>null</code>.
   *
   * @see #NEGATIVE_INFINITY_BYTE
   * @see #NEGATIVE_INFINITY_SHORT
   * @see #NEGATIVE_INFINITY_INTEGER
   * @see #NEGATIVE_INFINITY_LONG
   * @see #NEGATIVE_INFINITY_BIGINTEGER
   * @see #NEGATIVE_INFINITY_FLOAT
   * @see #NEGATIVE_INFINITY_DOUBLE
   * @see #POSITIVE_INFINITY_BYTE
   * @see #POSITIVE_INFINITY_SHORT
   * @see #POSITIVE_INFINITY_INTEGER
   * @see #POSITIVE_INFINITY_LONG
   * @see #POSITIVE_INFINITY_BIGINTEGER
   * @see #POSITIVE_INFINITY_FLOAT
   * @see #POSITIVE_INFINITY_DOUBLE
   */
  public static final Number UNKNOWN_INFINITY = null;

  /**
   * Constant representing negative infinity Byte: <code>null</code>.
   *
   * @see #UNKNOWN_INFINITY
   * @see #NEGATIVE_INFINITY_SHORT
   * @see #NEGATIVE_INFINITY_INTEGER
   * @see #NEGATIVE_INFINITY_LONG
   * @see #NEGATIVE_INFINITY_BIGINTEGER
   * @see #NEGATIVE_INFINITY_FLOAT
   * @see #NEGATIVE_INFINITY_DOUBLE
   */
  public static final Byte NEGATIVE_INFINITY_BYTE = Byte.class.cast(UNKNOWN_INFINITY);

  /**
   * Constant representing negative infinity Short: <code>null</code>.
   *
   * @see #UNKNOWN_INFINITY
   * @see #NEGATIVE_INFINITY_BYTE
   * @see #NEGATIVE_INFINITY_INTEGER
   * @see #NEGATIVE_INFINITY_LONG
   * @see #NEGATIVE_INFINITY_BIGINTEGER
   * @see #NEGATIVE_INFINITY_FLOAT
   * @see #NEGATIVE_INFINITY_DOUBLE
   */
  public static final Short NEGATIVE_INFINITY_SHORT = Short.class.cast(UNKNOWN_INFINITY);

  /**
   * Constant representing negative infinity Integer: <code>null</code>.
   *
   * @see #UNKNOWN_INFINITY
   * @see #NEGATIVE_INFINITY_BYTE
   * @see #NEGATIVE_INFINITY_SHORT
   * @see #NEGATIVE_INFINITY_LONG
   * @see #NEGATIVE_INFINITY_BIGINTEGER
   * @see #NEGATIVE_INFINITY_FLOAT
   * @see #NEGATIVE_INFINITY_DOUBLE
   */
  public static final Integer NEGATIVE_INFINITY_INTEGER = Integer.class.cast(UNKNOWN_INFINITY);

  /**
   * Constant representing negative infinity Long: <code>null</code>.
   *
   * @see #UNKNOWN_INFINITY
   * @see #NEGATIVE_INFINITY_BYTE
   * @see #NEGATIVE_INFINITY_SHORT
   * @see #NEGATIVE_INFINITY_INTEGER
   * @see #NEGATIVE_INFINITY_BIGINTEGER
   * @see #NEGATIVE_INFINITY_FLOAT
   * @see #NEGATIVE_INFINITY_DOUBLE
   */
  public static final Long NEGATIVE_INFINITY_LONG = Long.class.cast(UNKNOWN_INFINITY);

  /**
   * Constant representing negative infinity BigInteger: <code>null</code>.
   *
   * @see #UNKNOWN_INFINITY
   * @see #NEGATIVE_INFINITY_BYTE
   * @see #NEGATIVE_INFINITY_SHORT
   * @see #NEGATIVE_INFINITY_INTEGER
   * @see #NEGATIVE_INFINITY_LONG
   * @see #NEGATIVE_INFINITY_FLOAT
   * @see #NEGATIVE_INFINITY_DOUBLE
   */
  public static final BigInteger NEGATIVE_INFINITY_BIGINTEGER = BigInteger.class.cast(UNKNOWN_INFINITY);

  /**
   * Constant representing negative infinity Float: <code>{@link Double#NEGATIVE_INFINITY}</code>.
   *
   * @see Float#NEGATIVE_INFINITY
   * @see #UNKNOWN_INFINITY
   * @see #NEGATIVE_INFINITY_BYTE
   * @see #NEGATIVE_INFINITY_SHORT
   * @see #NEGATIVE_INFINITY_INTEGER
   * @see #NEGATIVE_INFINITY_LONG
   * @see #NEGATIVE_INFINITY_BIGINTEGER
   * @see #NEGATIVE_INFINITY_DOUBLE
   */
  public static final Float NEGATIVE_INFINITY_FLOAT = Float.NEGATIVE_INFINITY;

  /**
   * Constant representing negative infinity Double: <code>{@link Double#NEGATIVE_INFINITY}</code>.
   *
   * @see Double#NEGATIVE_INFINITY
   * @see #UNKNOWN_INFINITY
   * @see #NEGATIVE_INFINITY_BYTE
   * @see #NEGATIVE_INFINITY_SHORT
   * @see #NEGATIVE_INFINITY_INTEGER
   * @see #NEGATIVE_INFINITY_LONG
   * @see #NEGATIVE_INFINITY_BIGINTEGER
   * @see #NEGATIVE_INFINITY_FLOAT
   */
  public static final Double NEGATIVE_INFINITY_DOUBLE = Double.NEGATIVE_INFINITY;

  /**
   * Constant representing positive infinity BigInteger: <code>null</code>.
   *
   * @see #UNKNOWN_INFINITY
   * @see #POSITIVE_INFINITY_BYTE
   * @see #POSITIVE_INFINITY_SHORT
   * @see #POSITIVE_INFINITY_INTEGER
   * @see #POSITIVE_INFINITY_LONG
   * @see #POSITIVE_INFINITY_FLOAT
   * @see #POSITIVE_INFINITY_DOUBLE
   */
  public static final BigInteger POSITIVE_INFINITY_BIGINTEGER = BigInteger.class.cast(UNKNOWN_INFINITY);

  /**
   * Constant representing positive infinity Float: <code>{@link Float#POSITIVE_INFINITY}</code>.
   *
   * @see Float#POSITIVE_INFINITY
   * @see #UNKNOWN_INFINITY
   * @see #POSITIVE_INFINITY_BYTE
   * @see #POSITIVE_INFINITY_SHORT
   * @see #POSITIVE_INFINITY_INTEGER
   * @see #POSITIVE_INFINITY_LONG
   * @see #POSITIVE_INFINITY_BIGINTEGER
   * @see #POSITIVE_INFINITY_DOUBLE
   */
  public static final Float POSITIVE_INFINITY_FLOAT = Float.POSITIVE_INFINITY;

  /**
   * Constant representing positive infinity Double: <code>{@link Double#POSITIVE_INFINITY}</code>.
   *
   * @see Double#POSITIVE_INFINITY
   * @see #UNKNOWN_INFINITY
   * @see #POSITIVE_INFINITY_BYTE
   * @see #POSITIVE_INFINITY_SHORT
   * @see #POSITIVE_INFINITY_INTEGER
   * @see #POSITIVE_INFINITY_LONG
   * @see #POSITIVE_INFINITY_BIGINTEGER
   * @see #POSITIVE_INFINITY_FLOAT
   */
  public static final Double POSITIVE_INFINITY_DOUBLE = Double.POSITIVE_INFINITY;


  /**
   * Constant representing unknown NaN - not a number value (general, for all numeric types no explicit NaN
   * value is defined): <code>null</code>.
   *
   * @see #NAN_BYTE
   * @see #NAN_SHORT
   * @see #NAN_INTEGER
   * @see #NAN_LONG
   * @see #NAN_BIGINTEGER
   * @see #NAN_FLOAT
   * @see #NAN_DOUBLE
   */
  public static final Number UNKNOWN_NAN = null;

  /**
   * Constant representing NaN Short: <code>null</code>.
   *
   * @see #UNKNOWN_NAN
   * @see #NAN_BYTE
   * @see #NAN_INTEGER
   * @see #NAN_LONG
   * @see #NAN_BIGINTEGER
   * @see #NAN_FLOAT
   * @see #NAN_DOUBLE
   */
  public static final Short NAN_SHORT = Short.class.cast(UNKNOWN_NAN);

  /**
   * Constant representing NaN Integer: <code>null</code>.
   *
   * @see #UNKNOWN_NAN
   * @see #NAN_BYTE
   * @see #NAN_SHORT
   * @see #NAN_LONG
   * @see #NAN_BIGINTEGER
   * @see #NAN_FLOAT
   * @see #NAN_DOUBLE
   */
  public static final Integer NAN_INTEGER = Integer.class.cast(UNKNOWN_NAN);

  /**
   * Constant representing NaN Long: <code>null</code>.
   *
   * @see #UNKNOWN_NAN
   * @see #NAN_BYTE
   * @see #NAN_SHORT
   * @see #NAN_INTEGER
   * @see #NAN_BIGINTEGER
   * @see #NAN_FLOAT
   * @see #NAN_DOUBLE
   */
  public static final Long NAN_LONG = Long.class.cast(UNKNOWN_NAN);

  /**
   * Constant representing NaN BigInteger: <code>null</code>.
   *
   * @see #UNKNOWN_NAN
   * @see #NAN_BYTE
   * @see #NAN_SHORT
   * @see #NAN_INTEGER
   * @see #NAN_LONG
   * @see #NAN_FLOAT
   * @see #NAN_DOUBLE
   */
  public static final BigInteger NAN_BIGINTEGER = BigInteger.class.cast(UNKNOWN_NAN);

  /**
   * Constant representing NaN Float: <code>{@link Float#NaN}</code>.
   *
   * @see Float#NaN
   * @see #UNKNOWN_NAN
   * @see #NAN_BYTE
   * @see #NAN_SHORT
   * @see #NAN_INTEGER
   * @see #NAN_LONG
   * @see #NAN_BIGINTEGER
   * @see #NAN_DOUBLE
   */
  public static final Float NAN_FLOAT = Float.NaN;

  /**
   * Constant representing NaN Double: <code>{@link Double#NaN}</code>.
   *
   * @see Double#NaN
   * @see #UNKNOWN_NAN
   * @see #NAN_BYTE
   * @see #NAN_SHORT
   * @see #NAN_INTEGER
   * @see #NAN_LONG
   * @see #NAN_BIGINTEGER
   * @see #NAN_FLOAT
   */
  public static final Double NAN_DOUBLE = Double.NaN;

  /**
   * Constant representing unknown minimum value (general, for all numeric types no explicit maximum value is
   * defined): <code>null</code>.
   *
   * @see #UNKNOWN_MIN
   * @see #MIN_SHORT
   * @see #MIN_INTEGER
   * @see #MIN_LONG
   * @see #MIN_BIGINTEGER
   * @see #MIN_FLOAT
   * @see #MIN_DOUBLE
   */
  public static final Number UNKNOWN_MIN = null;

  /**
   * Constant representing minimum Byte: <code>{@link Byte#MIN_VALUE}</code>.
   *
   * @see Byte#MIN_VALUE
   * @see #UNKNOWN_MIN
   * @see #MIN_SHORT
   * @see #MIN_INTEGER
   * @see #MIN_LONG
   * @see #MIN_BIGINTEGER
   * @see #MIN_FLOAT
   * @see #MIN_DOUBLE
   */
  public static final Byte MIN_BYTE = Byte.MIN_VALUE;

  /**
   * Constant representing minimum Short: <code>{@link Short#MIN_VALUE}</code>.
   *
   * @see Short#MIN_VALUE
   * @see #UNKNOWN_MIN
   * @see #MIN_SHORT
   * @see #MIN_INTEGER
   * @see #MIN_LONG
   * @see #MIN_BIGINTEGER
   * @see #MIN_FLOAT
   * @see #MIN_DOUBLE
   */
  public static final Short MIN_SHORT = Short.MIN_VALUE;

  /**
   * Constant representing minimum Integer: <code>{@link Integer#MIN_VALUE}</code>.
   *
   * @see Integer#MIN_VALUE
   * @see #UNKNOWN_MIN
   * @see #MIN_SHORT
   * @see #MIN_INTEGER
   * @see #MIN_LONG
   * @see #MIN_BIGINTEGER
   * @see #MIN_FLOAT
   * @see #MIN_DOUBLE
   */
  public static final Integer MIN_INTEGER = Integer.MIN_VALUE;

  /**
   * Constant representing minimum Long: <code>{@link Long#MIN_VALUE}</code>.
   *
   * @see Long#MIN_VALUE
   * @see #UNKNOWN_MIN
   * @see #MIN_SHORT
   * @see #MIN_INTEGER
   * @see #MIN_LONG
   * @see #MIN_BIGINTEGER
   * @see #MIN_FLOAT
   * @see #MIN_DOUBLE
   */
  public static final Long MIN_LONG = Long.MIN_VALUE;

  /**
   * Constant representing minimum BigInteger: <code>null</code>.
   *
   * @see #UNKNOWN_MIN
   * @see #MIN_SHORT
   * @see #MIN_INTEGER
   * @see #MIN_LONG
   * @see #MIN_BIGINTEGER
   * @see #MIN_FLOAT
   * @see #MIN_DOUBLE
   */
  public static final BigInteger MIN_BIGINTEGER = BigInteger.class.cast(UNKNOWN_MIN);

  /**
   * Constant representing minimum Float: <code>{@link Float#MIN_VALUE}</code>.
   *
   * @see Float#MIN_VALUE
   * @see #UNKNOWN_MIN
   * @see #MIN_SHORT
   * @see #MIN_INTEGER
   * @see #MIN_LONG
   * @see #MIN_BIGINTEGER
   * @see #MIN_FLOAT
   * @see #MIN_DOUBLE
   */
  public static final Float MIN_FLOAT = Float.MIN_VALUE;

  /**
   * Constant representing minimum Double: <code>{@link Double#MIN_VALUE}</code>.
   *
   * @see Double#MIN_VALUE
   * @see #UNKNOWN_MIN
   * @see #MIN_SHORT
   * @see #MIN_INTEGER
   * @see #MIN_LONG
   * @see #MIN_BIGINTEGER
   * @see #MIN_FLOAT
   * @see #MIN_DOUBLE
   */
  public static final Double MIN_DOUBLE = Double.MIN_VALUE;

  /**
   * Constant representing unknown maximum value (general, for all numeric types no explicit maximum value is
   * defined): <code>null</code>.
   *
   * @see #MAX_SHORT
   * @see #MAX_INTEGER
   * @see #MAX_LONG
   * @see #MAX_BIGINTEGER
   * @see #MAX_FLOAT
   * @see #MAX_DOUBLE
   */
  public static final Number UNKNOWN_MAX = null;

  /**
   * Constant representing maximum Byte: <code>{@link Byte#MAX_VALUE}</code>.
   *
   * @see Byte#MAX_VALUE
   * @see #UNKNOWN_MAX
   * @see #MAX_SHORT
   * @see #MAX_INTEGER
   * @see #MAX_LONG
   * @see #MAX_BIGINTEGER
   * @see #MAX_FLOAT
   * @see #MAX_DOUBLE
   */
  public static final Byte MAX_BYTE = Byte.MAX_VALUE;

  /**
   * Constant representing maximum Short: <code>{@link Short#MAX_VALUE}</code>.
   *
   * @see Short#MAX_VALUE
   * @see #UNKNOWN_MAX
   * @see #MAX_BYTE
   * @see #MAX_INTEGER
   * @see #MAX_LONG
   * @see #MAX_BIGINTEGER
   * @see #MAX_FLOAT
   * @see #MAX_DOUBLE
   */
  public static final Short MAX_SHORT = Short.MAX_VALUE;

  /**
   * Constant representing maximum Integer: <code>{@link Integer#MAX_VALUE}</code>.
   *
   * @see Integer#MAX_VALUE
   * @see #UNKNOWN_MAX
   * @see #MAX_BYTE
   * @see #MAX_SHORT
   * @see #MAX_LONG
   * @see #MAX_BIGINTEGER
   * @see #MAX_FLOAT
   * @see #MAX_DOUBLE
   */
  public static final Integer MAX_INTEGER = Integer.MAX_VALUE;

  /**
   * Constant representing maximum Long: <code>{@link Long#MAX_VALUE}</code>.
   *
   * @see Long#MAX_VALUE
   * @see #UNKNOWN_MAX
   * @see #MAX_BYTE
   * @see #MAX_SHORT
   * @see #MAX_INTEGER
   * @see #MAX_BIGINTEGER
   * @see #MAX_FLOAT
   * @see #MAX_DOUBLE
   */
  public static final Long MAX_LONG = Long.MAX_VALUE;

  /**
   * Constant representing maximum BigInteger: <code>null</code>.
   *
   * @see #UNKNOWN_MAX
   * @see #MAX_BYTE
   * @see #MAX_SHORT
   * @see #MAX_INTEGER
   * @see #MAX_LONG
   * @see #MAX_FLOAT
   * @see #MAX_DOUBLE
   */
  public static final BigInteger MAX_BIGINTEGER = BigInteger.class.cast(UNKNOWN_MAX);

  /**
   * Constant representing maximum Float: <code>{@link Float#MAX_VALUE}</code>.
   *
   * @see Float#MAX_VALUE
   * @see #UNKNOWN_MAX
   * @see #MAX_BYTE
   * @see #MAX_SHORT
   * @see #MAX_INTEGER
   * @see #MAX_LONG
   * @see #MAX_BIGINTEGER
   * @see #MAX_DOUBLE
   */
  public static final Float MAX_FLOAT = Float.MAX_VALUE;

  /**
   * Constant representing maximum Double: <code>{@link Double#MAX_VALUE}</code>.
   *
   * @see Double#MAX_VALUE
   * @see #UNKNOWN_MAX
   * @see #MAX_BYTE
   * @see #MAX_SHORT
   * @see #MAX_INTEGER
   * @see #MAX_LONG
   * @see #MAX_BIGINTEGER
   * @see #MAX_FLOAT
   */
  public static final Double MAX_DOUBLE = Double.MAX_VALUE;

  /**
   * Gets number class.
   *
   * @return number class
   */
  public Class<T> getNumClass();

  /**
   * Gets zero.
   *
   * @return zero
   */
  public T getZero();

  /**
   * Gets negative infinity.
   *
   * @return negative infinity
   */
  public T getNegativeInfinity();

  /**
   * Gets positive infinity.
   *
   * @return positive infinity
   */
  public T getPositiveInfinity();

  /**
   * Gets maximum.
   *
   * @return maximum
   */
  public T getMax();

  /**
   * Gets minimum.
   *
   * @return minimum
   */
  public T getMin();

  /**
   * Gets NaN (not a number value).
   *
   * @return NaN
   */
  public T getNaN();

  /**
   * Gets size.
   *
   * @param value value, <code>null</code> permitted
   * @return size
   */
  public int getSize(Number value);

}

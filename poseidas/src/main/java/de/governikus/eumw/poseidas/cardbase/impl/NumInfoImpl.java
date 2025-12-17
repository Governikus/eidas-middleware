/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardbase.impl;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import de.governikus.eumw.poseidas.cardbase.AssertUtil;
import de.governikus.eumw.poseidas.cardbase.NumInfo;
import de.governikus.eumw.poseidas.cardbase.ObjectUtil;


/**
 * Implementation of number informations.
 *
 * @param <T> type of number
 * @author Jens Wothe, jw@bos-bremen.de
 */
public final class NumInfoImpl<T extends Number & Comparable<T>> implements NumInfo<T>
{

  /**
   * Constant of informations about number type Byte.
   *
   * @see Byte
   * @see NumInfo#ZERO_BYTE
   * @see NumInfo#NEGATIVE_INFINITY_BYTE
   * @see NumInfo#POSITIVE_INFINITY_BYTE
   * @see NumInfo#MIN_BYTE
   * @see NumInfo#MAX_BYTE
   * @see NumInfo#NAN_BYTE
   * @see Byte#SIZE
   * @see #SHORT
   * @see #INTEGER
   * @see #LONG
   * @see #BIGINTEGER
   * @see #FLOAT
   * @see #DOUBLE
   */
  private static final NumInfo<Byte> BYTE = new NumInfoImpl<>(Byte.class, ZERO_BYTE, NEGATIVE_INFINITY_BYTE,
                                                              NEGATIVE_INFINITY_BYTE, MIN_BYTE, MAX_BYTE, null,
                                                              Byte.SIZE);

  /**
   * Constant of informations about number type Short.
   *
   * @see Short
   * @see NumInfo#ZERO_SHORT
   * @see NumInfo#NEGATIVE_INFINITY_SHORT
   * @see NumInfo#POSITIVE_INFINITY_SHORT
   * @see NumInfo#MIN_SHORT
   * @see NumInfo#MAX_SHORT
   * @see NumInfo#NAN_SHORT
   * @see Short#SIZE
   * @see #BYTE
   * @see #INTEGER
   * @see #LONG
   * @see #BIGINTEGER
   * @see #FLOAT
   * @see #DOUBLE
   */
  private static final NumInfo<Short> SHORT = new NumInfoImpl<>(Short.class, ZERO_SHORT, NEGATIVE_INFINITY_SHORT,
                                                                NEGATIVE_INFINITY_SHORT, MIN_SHORT, MAX_SHORT,
                                                                NAN_SHORT, Short.SIZE);

  /**
   * Constant of informations about number type Integer.
   *
   * @see Integer
   * @see NumInfo#ZERO_INTEGER
   * @see NumInfo#NEGATIVE_INFINITY_INTEGER
   * @see NumInfo#POSITIVE_INFINITY_INTEGER
   * @see NumInfo#MIN_INTEGER
   * @see NumInfo#MAX_INTEGER
   * @see NumInfo#NAN_INTEGER
   * @see Integer#SIZE
   * @see #BYTE
   * @see #SHORT
   * @see #LONG
   * @see #BIGINTEGER
   * @see #FLOAT
   * @see #DOUBLE
   */
  private static final NumInfo<Integer> INTEGER = new NumInfoImpl<>(Integer.class, ZERO_INTEGER,
                                                                    NEGATIVE_INFINITY_INTEGER,
                                                                    NEGATIVE_INFINITY_INTEGER, MIN_INTEGER, MAX_INTEGER,
                                                                    NAN_INTEGER, Integer.SIZE);

  /**
   * Constant of informations about number type Long.
   *
   * @see Long
   * @see NumInfo#ZERO_LONG
   * @see NumInfo#NEGATIVE_INFINITY_LONG
   * @see NumInfo#POSITIVE_INFINITY_LONG
   * @see NumInfo#MIN_LONG
   * @see NumInfo#MAX_LONG
   * @see NumInfo#NAN_LONG
   * @see Long#SIZE
   * @see #BYTE
   * @see #SHORT
   * @see #INTEGER
   * @see #BIGINTEGER
   * @see #FLOAT
   * @see #DOUBLE
   */
  private static final NumInfo<Long> LONG = new NumInfoImpl<>(Long.class, ZERO_LONG, NEGATIVE_INFINITY_LONG,
                                                              NEGATIVE_INFINITY_LONG, MIN_LONG, MAX_LONG, NAN_LONG,
                                                              Long.SIZE);

  /**
   * Constant of informations about number type BigInteger.
   *
   * @see BigInteger
   * @see NumInfo#ZERO_BIGINTEGER
   * @see NumInfo#NEGATIVE_INFINITY_BIGINTEGER
   * @see NumInfo#POSITIVE_INFINITY_BIGINTEGER
   * @see NumInfo#MIN_BIGINTEGER
   * @see NumInfo#MAX_BIGINTEGER
   * @see NumInfo#NAN_BIGINTEGER
   * @see NumInfo#UNKNOWN_SIZE
   * @see #BYTE
   * @see #SHORT
   * @see #INTEGER
   * @see #LONG
   * @see #FLOAT
   * @see #DOUBLE
   */
  private static final NumInfo<java.math.BigInteger> BIGINTEGER = new NumInfoImpl<>(BigInteger.class, ZERO_BIGINTEGER,
                                                                                    NEGATIVE_INFINITY_BIGINTEGER,
                                                                                    POSITIVE_INFINITY_BIGINTEGER,
                                                                                    MIN_BIGINTEGER, MAX_BIGINTEGER,
                                                                                    NAN_BIGINTEGER, UNKNOWN_SIZE);

  /**
   * Constant of informations about number type Float.
   *
   * @see Float
   * @see NumInfo#ZERO_FLOAT
   * @see NumInfo#NEGATIVE_INFINITY_FLOAT
   * @see NumInfo#POSITIVE_INFINITY_FLOAT
   * @see NumInfo#MIN_FLOAT
   * @see NumInfo#MAX_FLOAT
   * @see NumInfo#NAN_FLOAT
   * @see Float#SIZE
   * @see #BYTE
   * @see #SHORT
   * @see #INTEGER
   * @see #LONG
   * @see #BIGINTEGER
   * @see #DOUBLE
   */
  private static final NumInfo<Float> FLOAT = new NumInfoImpl<>(Float.class, ZERO_FLOAT, NEGATIVE_INFINITY_FLOAT,
                                                                POSITIVE_INFINITY_FLOAT, MIN_FLOAT, MAX_FLOAT,
                                                                NAN_FLOAT, Float.SIZE);

  /**
   * Constant of informations about number type Double.
   *
   * @see Double
   * @see NumInfo#ZERO_DOUBLE
   * @see NumInfo#NEGATIVE_INFINITY_DOUBLE
   * @see NumInfo#POSITIVE_INFINITY_DOUBLE
   * @see NumInfo#MIN_DOUBLE
   * @see NumInfo#MAX_DOUBLE
   * @see NumInfo#NAN_DOUBLE
   * @see Double#SIZE
   * @see #BYTE
   * @see #SHORT
   * @see #INTEGER
   * @see #LONG
   * @see #BIGINTEGER
   * @see #FLOAT
   */
  private static final NumInfo<Double> DOUBLE = new NumInfoImpl<>(Double.class, ZERO_DOUBLE, NEGATIVE_INFINITY_DOUBLE,
                                                                  POSITIVE_INFINITY_DOUBLE, MIN_DOUBLE, MAX_DOUBLE,
                                                                  NAN_DOUBLE, Double.SIZE);

  /**
   * Constant list of number informations.
   *
   * @see #BYTE
   * @see #SHORT
   * @see #INTEGER
   * @see #LONG
   * @see #BIGINTEGER
   * @see #FLOAT
   * @see #DOUBLE
   */
  public static final List<NumInfo<?>> LIST_NUM_INFO;
  static
  {
    List<NumInfo<?>> tmp = new ArrayList<>();
    tmp.add(BYTE);
    tmp.add(SHORT);
    tmp.add(INTEGER);
    tmp.add(LONG);
    tmp.add(BIGINTEGER);
    tmp.add(DOUBLE);
    tmp.add(FLOAT);
    LIST_NUM_INFO = Collections.unmodifiableList(tmp);
  }

  // zero value
  private final T zero;

  // negative infinity value
  private final T negativeInfinity;

  // negative infinity value
  private final T positiveInfinity;

  // minimum value
  private final T min;

  // maximum value
  private final T max;

  // NaN value
  private final T nan;

  // number class
  private final Class<T> numClass;

  // size
  private final int size;

  /**
   * Constructor.
   *
   * @param numClass number class, <code>null</code> not permitted
   * @param zero zero value, <code>null</code> not permitted
   * @param negativeInfinity negative infinity value, <code>null</code> permitted ( {@link NumInfo#UNKNOWN_INFINITY})
   * @param positiveInfinity positive infinity value, <code>null</code> permitted ( {@link NumInfo#UNKNOWN_INFINITY})
   * @param min minimum value, <code>null</code> permitted ({@link NumInfo#UNKNOWN_MIN})
   * @param max maximum value, <code>null</code> permitted ({@link NumInfo#UNKNOWN_MAX})
   * @param nan not a number value, <code>null</code> permitted ({@link NumInfo#UNKNOWN_NAN})
   * @param size size value, for unknown size use {@link NumInfo#UNKNOWN_SIZE}, value must be greater equals
   *          {@link NumInfo#UNKNOWN_SIZE}
   * @throws IllegalArgumentException if one of the arguments is not valid
   */
  private NumInfoImpl(Class<T> numClass, T zero, T negativeInfinity, T positiveInfinity, T min, T max, T nan, int size)
  {
    super();
    AssertUtil.notNull(numClass, "number class");
    AssertUtil.notNull(zero, "zero");
    AssertUtil.greaterEquals(size, UNKNOWN_SIZE, "size");
    this.numClass = numClass;
    this.zero = zero;
    this.negativeInfinity = negativeInfinity;
    this.positiveInfinity = positiveInfinity;
    this.min = min;
    this.max = max;
    this.nan = nan;
    this.size = size;
  }

  /** {@inheritDoc} */
  @Override
  public T getNegativeInfinity()
  {
    return this.negativeInfinity;
  }

  /** {@inheritDoc} */
  @Override
  public T getPositiveInfinity()
  {
    return this.positiveInfinity;
  }

  /** {@inheritDoc} */
  @Override
  public T getMin()
  {
    return this.min;
  }

  /** {@inheritDoc} */
  @Override
  public T getMax()
  {
    return this.max;
  }

  /** {@inheritDoc} */
  @Override
  public T getNaN()
  {
    return this.nan;
  }

  /** {@inheritDoc} */
  @Override
  public Class<T> getNumClass()
  {
    return this.numClass;
  }

  /** {@inheritDoc} */
  @Override
  public T getZero()
  {
    return this.zero;
  }

  /** {@inheritDoc} */
  @Override
  public int getSize(Number value)
  {
    if (!this.numClass.isInstance(value))
    {
      return -1;
    }
    if (ObjectUtil.notNull(value) && BigInteger.class.equals(value.getClass()))
    {
      return BigInteger.class.cast(value).toByteArray().length * 8;
    }
    return this.size;
  }

  /** {@inheritDoc} */
  @Override
  public String toString()
  {
    return super.toString() + " (Class: " + this.numClass + ", zero: " + this.zero + ", negative infinity: "
           + this.negativeInfinity + ", positive infinity: " + this.positiveInfinity + ", minimum: " + this.min
           + ", maximum: " + this.max + ", NaN: " + this.nan + ", size: " + this.size + ")";
  }

}

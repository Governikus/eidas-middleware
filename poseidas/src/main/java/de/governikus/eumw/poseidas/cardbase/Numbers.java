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



/**
 * Utilties around number instances.
 *
 * @author Jens Wothe, jw@bos-bremen.de
 */
public class Numbers
{

  /**
   * Checks value is positive.
   * <p>
   * Note: <code>null</code> value representing unknown infinite or NaN ({@link NumInfo#UNKNOWN_INFINITY} and
   * {@link NumInfo#UNKNOWN_NAN}) is a negative infinity, positive infinity and NaN, but not a minimum or
   * maximum. Additionally it is positive and negative and not zero.
   * </p>
   *
   * @param <T> type of number
   * @param value value, <code>null</code> permitted, unknown number type not permitted
   * @return <code>true</code> for positive value, <code>false</code> otherwise (especially for
   *         <code>null</code>)
   * @throws IllegalArgumentException if value <code>null</code> or unknown number type
   * @see NumInfo#getZero()
   * @see NumInfo#UNKNOWN_ZERO
   * @see NumInfo#ZERO_BYTE
   * @see NumInfo#ZERO_SHORT
   * @see NumInfo#ZERO_INTEGER
   * @see NumInfo#ZERO_LONG
   * @see NumInfo#ZERO_BIGINTEGER
   * @see NumInfo#ZERO_FLOAT
   * @see NumInfo#ZERO_DOUBLE
   */
  static <T extends Number & Comparable<T>> boolean isPositive(T value)
  {
    if (ObjectUtil.isEquals(value, NumInfo.UNKNOWN_INFINITY))
    {
      return true;
    }
    return isGreater(value, getNumInfo(value).getZero());
  }

  /**
   * Checks value A is greater than B.
   * <p>
   * Note: <code>null</code> value representing unknown infinity ({@link NumInfo#UNKNOWN_INFINITY}, identical
   * to {@link NumInfo#UNKNOWN_NAN}) is greater and less than every other value, negative infinity is less
   * than an every other value and positive infinity is greater than an every other value.
   * </p>
   *
   * @param <T> type of number
   * @param a value A, <code>null</code> permitted
   * @param b value B, <code>null</code> permitted
   * @return <code>true</code> for a less than b, <code>null</code> value is greater than every other value
   * @see NumInfo#UNKNOWN_INFINITY
   * @see NumInfo#NEGATIVE_INFINITY_BYTE
   * @see NumInfo#NEGATIVE_INFINITY_SHORT
   * @see NumInfo#NEGATIVE_INFINITY_INTEGER
   * @see NumInfo#NEGATIVE_INFINITY_LONG
   * @see NumInfo#NEGATIVE_INFINITY_BIGINTEGER
   * @see NumInfo#NEGATIVE_INFINITY_FLOAT
   * @see NumInfo#NEGATIVE_INFINITY_DOUBLE
   * @see NumInfo#POSITIVE_INFINITY_BYTE
   * @see NumInfo#POSITIVE_INFINITY_SHORT
   * @see NumInfo#POSITIVE_INFINITY_INTEGER
   * @see NumInfo#POSITIVE_INFINITY_LONG
   * @see NumInfo#POSITIVE_INFINITY_BIGINTEGER
   * @see NumInfo#POSITIVE_INFINITY_FLOAT
   * @see NumInfo#POSITIVE_INFINITY_DOUBLE
   */
  private static <T extends Number & Comparable<T>> boolean isGreater(T a, T b)
  {
    int c = compareTo(a, b);
    return c == 1;
  }

  /**
   * Compares value A with the value B for order. Returns a negative integer, zero, or a positive integer as
   * value A is less than, equal to, or greater than the value B.
   * <p>
   * Note: <code>null</code> value representing infinite ({@link NumInfo#UNKNOWN_INFINITY}) is greater than
   * every other value.
   * </p>
   *
   * @param <T> type of number
   * @param a value A, <code>null</code> permitted representing negative infinity
   * @param b value B, <code>null</code> permitted representing positive infinity
   * @return <code>-1</code>, zero, or <code></code> as value A is less than, equals to or greater than value
   *         B
   * @see NumInfo#UNKNOWN_INFINITY
   * @see NumInfo#NEGATIVE_INFINITY_BYTE
   * @see NumInfo#NEGATIVE_INFINITY_SHORT
   * @see NumInfo#NEGATIVE_INFINITY_INTEGER
   * @see NumInfo#NEGATIVE_INFINITY_LONG
   * @see NumInfo#NEGATIVE_INFINITY_BIGINTEGER
   * @see NumInfo#NEGATIVE_INFINITY_FLOAT
   * @see NumInfo#NEGATIVE_INFINITY_DOUBLE
   * @see ObjectUtil#isEquals(Object, Object)
   */
  private static <T extends Number & Comparable<T>> int compareTo(T a, T b)
  {
    int r = 0;
    boolean aInfinity = ObjectUtil.isEquals(NumInfo.UNKNOWN_INFINITY, a);
    boolean bInfinity = ObjectUtil.isEquals(NumInfo.UNKNOWN_INFINITY, b);
    boolean aNaN = !aInfinity && (ObjectUtil.isEquals(Float.NaN, a) || ObjectUtil.isEquals(Double.NaN, a));
    boolean bNaN = !bInfinity && (ObjectUtil.isEquals(Float.NaN, b) || ObjectUtil.isEquals(Double.NaN, b));
    if (!aInfinity && !bInfinity)
    {
      r = a.compareTo(b);
      if (r > 0)
      {
        r = 1;
      }
      else if (r < 0)
      {
        r = -1;
      }
      else
      {
        r = 0;
      }
    }
    else if (aInfinity && bInfinity)
    {
      r = 0;
    }
    else if (aInfinity)
    {
      r = 1;
    }
    else if (bInfinity)
    {
      r = -1;
    }
    // special cases for Double/Float with defined NaN values
    // Double/Float: every value (including NEGATIVE_INFINITY) compares with NaN as -1, NaN less than every
    // value
    // Double/Float: NaN compares with every value (including POSITIVE_INFINITY) as 1, NaN greater than every
    // value
    if ((aInfinity && bNaN) || (aNaN && bInfinity))
    {
      // opposite result as for normal infinity
      r *= -1;
    }
    return r;
  }

  /**
   * Gets number informations related to type of value.
   * <p>
   * Note: <code>null</code> for <code>null</code> value representing infinite (
   * {@link NumInfo#UNKNOWN_INFINITY}) or NaN.
   * </p>
   *
   * @param <T> type of number
   * @param value value, <code>null</code> permitted, unknown number type not permitted
   * @return number informations, <code>null</code> for <code>null</code> value
   * @throws IllegalArgumentException if value class not of known number type
   * @see NumInfoUtil#getNumInfo(Class)
   * @see ObjectUtil#isNull(Object)
   */
  private static <T extends Number & Comparable<T>> NumInfo<T> getNumInfo(T value)
  {
    if (ObjectUtil.isNull(value))
    {
      return null;
    }
    Class<T> clazz = cast(value.getClass());
    return NumInfoUtil.getNumInfo(clazz);
  }

  /**
   * Cast a number extending Class to a Class extending Number and implementing Comparable.
   *
   * @param <T> type of Class extending Number and implementing Comparable
   * @param typeClass typeClass, <code>null</code> not permitted, Class must be assignable from {@link Number}
   *          and {@link Comparable}
   * @return casted Class
   * @throws IllegalArgumentException if type class <code>null</code> or not valid
   */
  @SuppressWarnings("unchecked")
  private static <T extends Number & Comparable<T>> Class<T> cast(Class<? extends Number> typeClass)
  {
    AssertUtil.notNull(typeClass, "number class");
    if (!Comparable.class.isAssignableFrom(typeClass))
    {
      throw new IllegalArgumentException("Comparable must be assignable from type class");
    }
    return (Class<T>)typeClass;
  }

}

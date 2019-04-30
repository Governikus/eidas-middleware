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

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.util.Collection;
import java.util.Formatter;


/**
 * Utilities for general testing of arguments and generating {@link IllegalArgumentException} with unified
 * messages.
 *
 * @author Jens Wothe, jw@bos-bremen.de
 */
public final class AssertUtil
{

  /**
   * Constant of error message for check numeric value is positive (greater than <code>0</code>).
   */
  private static final String MESSAGE_CHECK_FAILED_POSITIVE = "%1s expected to be positive, expected: value > 0, found: %2s <= 0";



  /**
   * Constant used as default name of arguments during check: <tt>values</tt>.
   *
   * @see #greaterEquals(int, int, String)
   * @see #equals(BigInteger, BigInteger, String)
   * @see #equals(Class, Class, String)
   * @see #equals(long, long, String)
   */
  private static final String DEFAULT_ARGUMENTS_NAME = "values";

  /**
   * Constant of error message for check numeric value is zero or positive (greater equals than <code>0</code>
   * ).
   *
   * @see #zeroOrPositive(int, String)
   */
  private static final String MESSAGE_CHECK_FAILED_ZERO_OR_POSITIVE = "%1s expected to be zero or positive, expected: value >= 0, found: %2s < 0";

  /**
   * Constant of error message for equality check of two values failed because values are not equal.
   *
   * @see #equals(long, long, String)
   */
  private static final String MESSAGE_CHECK_FAILED_EQUALS = "%1s expected to be equal, %2s <> %3s, expected: %4s";

  /**
   * Constant of error message for checkNotNull failed because Object is <code>null</code>.
   *
   * @see #notNull(Object, String)
   */
  private static final String MESSAGE_CHECK_FAILED_OBJECT_NULL = "%1s not permitted as null";

  /**
   * Constant of error message for check notNullOrEmpty failed because array is <code>null</code> or empty.
   *
   * @see #notNullOrEmpty(byte[], String)
   */
  private static final String MESSAGE_CHECK_FAILED_ARRAY_NULL_OR_EMPTY = "%1s not permitted as null or empty array";

  /**
   * Constant of error message for check notNullOrEmpty failed because String is <code>null</code> or empty.
   *
   * @see #notNullOrEmpty(String, String)
   */
  private static final String MESSAGE_CHECK_FAILED_STRING_NULL_OR_EMPTY = "%1s not permitted as null or empty String";

  /**
   * Constant of error message for check numeric value A is greater equals than value B (A >= B).
   *
   * @see #greaterEquals(int, int, String)
   */
  private static final String MESSAGE_CHECK_FAILED_NUM_GREATER_EQUALS = "%1s not as expected, expected relation '>=', found: %2s < %3s";

  /**
   * Constant of error message for check notNullOrEmpty failed because Collection is <code>null</code> or
   * empty.
   *
   * @see #notNullOrEmpty(Collection, String)
   */
  private static final String MESSAGE_CHECK_FAILED_COLLECTION_NULL_OR_EMPTY = "Collection%1sis not permitted as null or empty Collection";

  /**
   * Constructor.
   */
  private AssertUtil()
  {
    super();
  }

  /**
   * Checks Object is not <code>null</code>.
   *
   * @param object Object to check
   * @param message optional message to used as argument for formatting message, <code>null</code> or empty
   *          String is permitted
   * @throws IllegalArgumentException if Object is <code>null</code>
   * @see #MESSAGE_CHECK_FAILED_OBJECT_NULL
   */
  public static void notNull(Object object, String message)
  {
    if (object == null)
    {
      throw new IllegalArgumentException(format(MESSAGE_CHECK_FAILED_OBJECT_NULL,
                                                makeMessage(message, "Object")));
    }
  }

  /**
   * Checks array is not <code>null</code> or empty and returns array if not.
   *
   * @param array array
   * @param message optional message to used as argument for formatting message, <code>null</code> or empty
   *          String is permitted
   * @return array, if check ok
   * @throws IllegalArgumentException if array is <code>null</code> or empty
   * @see #MESSAGE_CHECK_FAILED_ARRAY_NULL_OR_EMPTY
   */
  public static final byte[] notNullOrEmpty(byte[] array, String message)
  {
    if (ArrayUtil.isNullOrEmpty(array))
    {
      throw new IllegalArgumentException(format(MESSAGE_CHECK_FAILED_ARRAY_NULL_OR_EMPTY,
                                                makeMessage(message, "array")));
    }
    return array;
  }

  /**
   * Checks String is not <code>null</code> or empty.
   *
   * @param s String
   * @param message optional message to used as argument for formatting message, <code>null</code> or empty
   *          String is permitted
   * @return s
   * @throws IllegalArgumentException if String is <code>null</code> or empty
   * @see #MESSAGE_CHECK_FAILED_STRING_NULL_OR_EMPTY
   */
  public static final String notNullOrEmpty(String s, String message)
  {
    if (s == null || s.length() == 0)
    {
      throw new IllegalArgumentException(format(MESSAGE_CHECK_FAILED_STRING_NULL_OR_EMPTY, (message != null
        ? message : "String")));
    }
    return s;
  }

  /**
   * Checks Collection is not <code>null</code> or empty.
   *
   * @param collection Collection
   * @param message optional message to used as argument for formatting message, <code>null</code> or empty
   *          String is permitted
   * @throws IllegalArgumentException if Collection is <code>null</code> or empty
   * @see CollectionUtil#isNull(Collection)
   * @see #MESSAGE_CHECK_FAILED_COLLECTION_NULL_OR_EMPTY
   */
  public static final void notNullOrEmpty(Collection<?> collection, String message)
  {
    if (CollectionUtil.isNullOrEmpty(collection))
    {
      throw new IllegalArgumentException(format(MESSAGE_CHECK_FAILED_COLLECTION_NULL_OR_EMPTY,
                                                makeSpaceMessageSpace(message)));
    }
  }

  /**
   * Checks array is not <code>null</code> or empty and returns array if not.
   *
   * @param array array
   * @param message optional message to used as argument for formatting message, <code>null</code> or empty
   *          String is permitted
   * @return array, if check ok
   * @throws IllegalArgumentException if array is <code>null</code> or empty
   * @see ArrayUtil#isNull(Object[])
   * @see StringUtil#format(String, Object...)
   * @see #MESSAGE_CHECK_FAILED_ARRAY_NULL_OR_EMPTY
   */
  public static final Object[] notNullOrEmpty(Object[] array, String message)
  {
    if (ArrayUtil.isNullOrEmpty(array))
    {
      throw new IllegalArgumentException(StringUtil.format(MESSAGE_CHECK_FAILED_ARRAY_NULL_OR_EMPTY,
                                                           makeMessage(message, "array")));
    }
    return array;
  }

  /**
   * Checks Object is not <code>null</code> and returns Object if not.
   *
   * @param <T> type of object
   * @param object Object to check
   * @param message optional message to used as argument for formatting message, <code>null</code> or empty
   *          String is permitted
   * @return object
   * @throws IllegalArgumentException if Object is <code>null</code>
   * @see #MESSAGE_CHECK_FAILED_OBJECT_NULL
   */
  public static <T extends Object> T notNullReturn(T object, String message)
  {
    if (object == null)
    {
      throw new IllegalArgumentException(format(MESSAGE_CHECK_FAILED_OBJECT_NULL,
                                                makeMessage(message, "Object")));
    }
    return object;
  }

  /**
   * Checks value A is greater than or equal to value B.
   *
   * @param a value A
   * @param b value B
   * @param message message to used as argument for formatting message, <code>null</code> or empty String is
   *          permitted
   * @throws IllegalArgumentException if value A not greater than or equal to value B
   */
  public static void greaterEquals(int a, int b, String message)
  {
    if (a < b)
    {
      throw new IllegalArgumentException(format(MESSAGE_CHECK_FAILED_NUM_GREATER_EQUALS,
                                                message != null ? message : DEFAULT_ARGUMENTS_NAME,
                                                a,
                                                b));
    }
  }

  private static String makeMessage(String message, String defaultName)
  {
    return (message != null ? message : defaultName);
  }

  /**
   * Checks value1 equals value2.
   *
   * @param value1 value1
   * @param value2 value2
   * @param message optional message to used as argument for formatting message, <code>null</code> or empty
   *          String is permitted
   * @throws IllegalArgumentException if values not equal
   */
  public static void equals(long value1, long value2, String message)
  {
    if (value1 != value2)
    {
      throw new IllegalArgumentException(format(MESSAGE_CHECK_FAILED_EQUALS,
                                                message != null ? message : DEFAULT_ARGUMENTS_NAME,
                                                value1,
                                                value2,
                                                value1));
    }
  }

  /**
   * Checks value1 equals value2.
   *
   * @param value1 value1
   * @param value2 value2
   * @param message optional message to used as argument for formatting message, <code>null</code> or empty
   *          String is permitted
   * @throws IllegalArgumentException if values not equal
   */
  public static void equals(Class<?> value1, Class<?> value2, String message)
  {
    if (value1 != value2)
    {
      throw new IllegalArgumentException(format(MESSAGE_CHECK_FAILED_EQUALS,
                                                message != null ? message : DEFAULT_ARGUMENTS_NAME,
                                                value1,
                                                value2,
                                                value1));
    }
  }

  /**
   * Checks value1 equals value2.
   *
   * @param value1 value1
   * @param value2 value2
   * @param message optional message to used as argument for formatting message, <code>null</code> or empty
   *          String is permitted
   * @throws IllegalArgumentException if values not equal
   */
  public static void equals(BigInteger value1, BigInteger value2, String message)
  {
    if (value1 == value2)
    {
      return;
    }
    else if ((value1 == null && value2 != null) || (value1 != null && value2 == null)
             || !value1.equals(value2))
    {
      throw new IllegalArgumentException(format(MESSAGE_CHECK_FAILED_EQUALS,
                                                message != null ? message : DEFAULT_ARGUMENTS_NAME,
                                                value1,
                                                value2,
                                                value1));
    }
  }

  /**
   * Checks value is zero or positive.
   *
   * @param value value
   * @param message message to used as argument for formatting message, <code>null</code> or empty String is
   *          permitted
   * @throws IllegalArgumentException if value not zero or positive
   */
  public static void zeroOrPositive(int value, String message)
  {
    if (value < 0)
    {
      throw new IllegalArgumentException(format(MESSAGE_CHECK_FAILED_ZERO_OR_POSITIVE,
                                                makeMessage(message, "value"),
                                                value));
    }
  }

  /**
   * Formats string using format and arguments.
   *
   * @param format format
   * @param args arguments
   * @return formatted String, <code>null</code> if format failed
   * @see Formatter#format(String, Object...)
   */
  private static final String format(String format, Object... args)
  {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (Formatter f = new Formatter(baos))
    {
      f.format(format, args);
    }
    return new String(baos.toByteArray());
  }

  private static String makeSpaceMessageSpace(String message)
  {
    return message != null && message.length() > 0 ? " " + message + " " : " ";
  }

  /**
   * Checks value is positive.
   * <p>
   * Note: <code>null</code> value representing infinite ({@link NumInfo#UNKNOWN_INFINITY}) is not positive.
   * </p>
   *
   * @param <T> type of number
   * @param value value, <code>null</code> permitted
   * @param message message to used as argument for formatting message, <code>null</code> or empty String is
   *          permitted
   * @throws IllegalArgumentException if value not positive
   */
  public static <T extends Number & Comparable<T>> void positive(T value, String message)
  {
    if (!Numbers.isPositive(value))
    {
      throw new IllegalArgumentException(
                                         StringUtil.format(MESSAGE_CHECK_FAILED_POSITIVE,
                                                           makeMessage(message, "value"),
                                                           value));
    }
  }

}

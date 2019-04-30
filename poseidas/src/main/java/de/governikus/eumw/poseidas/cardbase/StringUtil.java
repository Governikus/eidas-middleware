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
import java.util.Formatter;



/**
 * Some convenience functions for Strings.
 *
 * @see ArrayUtil
 * @see ByteUtil
 * @see AssertUtil
 * @see CollectionUtil
 * @see Hex
 * @see ObjectUtil
 * @author Jens Wothe, jw@bos-bremen.de
 */
public final class StringUtil
{

  /**
   * Constant of error message for isEmpty failed because String is <code>null</code>.
   *
   * @see #isEmpty(String)
   */
  private static final String MESSAGE_IS_EMPTY_FAILED_STRING_NULL = "String not permitted as null";

  /**
   * Constructor.
   */
  private StringUtil()
  {
    super();
  }

  /**
   * Checks a String is empty.
   *
   * @param s String to check, <code>null</code> not permitted
   * @return <code>true</code>, if String is empty, otherwise <code>false</code>
   * @throws IllegalArgumentException if String is <code>null</code>
   * @see #isNull(String)
   * @see #isNullOrEmpty(String)
   * @see String#length()
   * @see #MESSAGE_IS_EMPTY_FAILED_STRING_NULL
   */
  private static final boolean isEmpty(String s)
  {
    if (s == null)
    {
      throw new IllegalArgumentException(MESSAGE_IS_EMPTY_FAILED_STRING_NULL);
    }
    return s.length() == 0;
  }

  /**
   * Checks a String is not empty.
   *
   * @param s String to check, <code>null</code> not permitted
   * @return <code>true</code>, if String is not empty, otherwise <code>false</code>
   * @throws IllegalArgumentException if String is <code>null</code>
   * @see #notNull(String)
   * @see #notNullOrEmpty(String)
   */
  public static final boolean notEmpty(String s)
  {
    return !isEmpty(s);
  }

  /**
   * Checks a String is <code>null</code>.
   *
   * @param s String to check
   * @return <code>true</code>, if String is <code>null</code>, otherwise <code>false</code>
   * @see #isEmpty(String)
   * @see #isNullOrEmpty(String)
   */
  private static final boolean isNull(String s)
  {
    return s == null;
  }

  /**
   * Checks a String is <code>null</code> or empty.
   *
   * @param s String to check
   * @return <code>true</code>, if String is <code>null</code> or empty, otherwise <code>false</code>
   * @see #isNull(String)
   * @see #isEmpty(String)
   */
  private static final boolean isNullOrEmpty(String s)
  {
    return isNull(s) || isEmpty(s);
  }

  /**
   * Checks a String is not <code>null</code> or empty.
   *
   * @param s String to check
   * @return <code>true</code>, if String is not <code>null</code> or empty, otherwise <code>false</code>
   * @see #notNull(String)
   * @see #notEmpty(String)
   */
  public static final boolean notNullOrEmpty(String s)
  {
    return !isNullOrEmpty(s);
  }

  /**
   * Formats string using format and arguments.
   *
   * @param format format
   * @param args arguments
   * @return formatted String, <code>null</code> if format failed
   * @see Formatter#format(String, Object...)
   */
  static final String format(String format, Object... args)
  {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (Formatter f = new Formatter(baos))
    {
      f.format(format, args);
    }
    return new String(baos.toByteArray());
  }

}

/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardbase;

import java.util.Arrays;


/**
 * Some additional convenience functions for arrays.
 * 
 * @see Arrays
 * @author Jens Wothe, jw@bos-bremen.de
 */
public final class ArrayUtil
{

  /**
   * Constant of error message for isEmpty failed because array is <code>null</code>.
   * 
   * @see #isEmpty(byte[])
   */
  private static final String MESSAGE_FAILED_ARRAY_NULL = "array not permitted as null";

  /**
   * Constructor.
   */
  private ArrayUtil()
  {
    super();
  }

  /**
   * Checks array is <code>null</code> or empty.
   * 
   * @param array array to check
   * @return <code>true</code>, if array is <code>null</code> or empty, otherwise <code>false</code>
   * @see #isNull(byte[])
   * @see #isEmpty(byte[])
   */
  public static final boolean isNullOrEmpty(byte[] array)
  {
    return isNull(array) || isEmpty(array);
  }



  /**
   * Checks array is <code>null</code> or empty.
   * 
   * @param array array to check
   * @return <code>true</code>, if array is <code>null</code> or empty, otherwise <code>false</code>
   * @see #isNull(Object[])
   * @see #isEmpty(Object[])
   */
  public static final boolean isNullOrEmpty(Object[] array)
  {
    return isNull(array) || isEmpty(array);
  }

  /**
   * Checks array is <code>null</code> or empty.
   * 
   * @param array array to check
   * @return <code>true</code>, if array is <code>null</code> or empty, otherwise <code>false</code>
   * @see #isNull(int[])
   * @see #isEmpty(int[])
   */
  public static final boolean isNullOrEmpty(int[] array)
  {
    return isNull(array) || isEmpty(array);
  }

  /**
   * Checks array is <code>null</code>.
   * 
   * @param array array to check
   * @return <code>true</code>, if array is <code>null</code>, otherwise <code>false</code>
   * @see #isEmpty(byte[])
   * @see #isNullOrEmpty(byte[])
   */
  private static final boolean isNull(byte[] array)
  {
    return array == null;
  }

  /**
   * Checks array is <code>null</code>.
   * 
   * @param array array to check
   * @return <code>true</code>, if array is <code>null</code>, otherwise <code>false</code>
   * @see #isEmpty(Object[])
   * @see #isNullOrEmpty(Object[])
   */
  private static final boolean isNull(Object[] array)
  {
    return array == null;
  }

  /**
   * Checks array is <code>null</code>.
   * 
   * @param array array to check
   * @return <code>true</code>, if array is <code>null</code>, otherwise <code>false</code>
   * @see #isEmpty(int[])
   * @see #isNullOrEmpty(int[])
   */
  private static final boolean isNull(int[] array)
  {
    return array == null;
  }

  /**
   * Checks array is empty.
   * 
   * @param array array to check, <code>null</code> not permitted
   * @return <code>true</code>, if array is empty, otherwise <code>false</code>
   * @throws IllegalArgumentException if array is <code>null</code>
   * @see #isNull(byte[])
   * @see #isNullOrEmpty(byte[])
   * @see #MESSAGE_FAILED_ARRAY_NULL
   */
  private static final boolean isEmpty(byte[] array)
  {
    if (array == null)
    {
      throw new IllegalArgumentException(MESSAGE_FAILED_ARRAY_NULL);
    }
    return array.length == 0;
  }

  /**
   * Checks array is empty.
   * 
   * @param array array to check, <code>null</code> not permitted
   * @return <code>true</code>, if array is empty, otherwise <code>false</code>
   * @throws IllegalArgumentException if array is <code>null</code>
   * @see #isNull(Object[])
   * @see #isNullOrEmpty(Object[])
   * @see #MESSAGE_FAILED_ARRAY_NULL
   */
  private static final boolean isEmpty(Object[] array)
  {
    if (array == null)
    {
      throw new IllegalArgumentException(MESSAGE_FAILED_ARRAY_NULL);
    }
    return array.length == 0;
  }

  /**
   * Checks array is empty.
   * 
   * @param array array to check, <code>null</code> not permitted
   * @return <code>true</code>, if array is empty, otherwise <code>false</code>
   * @throws IllegalArgumentException if array is <code>null</code>
   * @see #isNull(int[])
   * @see #isNullOrEmpty(int[])
   * @see #MESSAGE_FAILED_ARRAY_NULL
   */
  private static final boolean isEmpty(int[] array)
  {
    if (array == null)
    {
      throw new IllegalArgumentException(MESSAGE_FAILED_ARRAY_NULL);
    }
    return array.length == 0;
  }

}

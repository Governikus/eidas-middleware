/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardbase;

import java.util.Comparator;



/**
 * Some convenience functions for Object.
 *
 * @see ArrayUtil
 * @see ByteUtil
 * @see AssertUtil
 * @see CollectionUtil
 * @see Hex
 * @see StringUtil
 * @author Jens Wothe, jw@bos-bremen.de
 */
public final class ObjectUtil
{

  /**
   * Constant of result for comparison first Object equal to second Object: zero - <code>0</code>.
   *
   * @see Comparator#compare(Object, Object)
   */
  private static final int COMPARE_RESULT_FIRST_EQUAL_TO_SECOND = 0;

  /**
   * Constant of result for comparison first Object less than second Object: negative integer - <code>-1</code>.
   *
   * @see Comparator#compare(Object, Object)
   */
  private static final int COMPARE_RESULT_FIRST_LESS_SECOND = -1;

  /**
   * Checks a Object is <code>null</code>.
   *
   * @param o Object to check
   * @return <code>true</code>, if Object is <code>null</code>, otherwise <code>false</code>
   * @see #isEqualsByReference(Object, Object)
   */
  static final boolean isNull(Object o)
  {
    return isEqualsByReference(o, null);
  }

  /**
   * Checks a Object is not <code>null</code>.
   *
   * @param o Object to check
   * @return <code>false</code>, if Object is <code>null</code>, otherwise <code>true</code>
   * @see #notEqualsByReference(Object, Object)
   */
  public static final boolean notNull(Object o)
  {
    return notEqualsByReference(o, null);
  }

  /**
   * Checks one Object is equals to another Object (using default mode and no comparator).
   *
   * @param o1 one Object, <code>null</code> permitted
   * @param o2 another Object, <code>null</code> permitted
   * @return <code>true</code>, if Objects are equal, otherwise <code>false</code>
   * @see #isEquals(Object, Object, EqualsMode, Comparator)
   */
  static boolean isEquals(Object o1, Object o2)
  {
    return isEquals(o1, o2, DEFAULT_EQUALS_MODE, null);
  }

  /**
   * Checks one Object is equals another Object.
   * <p>
   * Check according to following order:
   * <ol>
   * <li>reference is equals or both <code>null</code> - <code>true</code></li>
   * <li>only Object one of the Objects is <code>null</code> - <code>false</code></li>
   * <li>use {@link Object#equals(Object)} - related to implementation and used check mode</li>
   * <li>[check using optional given Comparator using {@link Comparator#compare(Object, Object)}, if Objects not equals
   * - related to implementation of Comparator]</li>
   * </ol>
   * </p>
   *
   * @param o1 one Object, <code>null</code> permitted
   * @param o2 another Object, <code>null</code> permitted
   * @param equalsMode mode for using {@link Object#equals(Object)}, <code>null</code> permitted and default mode is
   *          used
   * @param comparator optional Comparator, <code>null</code> permitted, please check documentation of Comparator
   *          according to default JavaDoc hints about implementation and equality and result
   *          {@link #COMPARE_RESULT_FIRST_EQUAL_TO_SECOND}
   * @return <code>true</code>, if Objects are equal, otherwise <code>false</code>
   * @see #DEFAULT_EQUALS_MODE
   * @see EqualsMode
   */
  private static boolean isEquals(Object o1, Object o2, final EqualsMode equalsMode, Comparator<Object> comparator)
  {
    EqualsMode tmpEqualsMode = equalsMode;
    if (ObjectUtil.isNull(equalsMode))
    {
      tmpEqualsMode = DEFAULT_EQUALS_MODE;
    }
    boolean result = false;
    if (notEqualsByReference(o1, o2))
    {
      // if both Objects not null compare them by mode and optional with comparator
      if (ObjectUtil.notNull(o1) && ObjectUtil.notNull(o2))
      {
        // internal equals compare of instance implementation
        result = tmpEqualsMode.compare(o1, o2) == COMPARE_RESULT_FIRST_EQUAL_TO_SECOND;
        // comparator equals if comparator given and current result is false
        if (!result && ObjectUtil.notNull(comparator))
        {
          result = comparator.compare(o1, o2) == COMPARE_RESULT_FIRST_EQUAL_TO_SECOND;
        }
      }
    }
    else
    {
      // equals by reference
      result = true;
    }
    return result;
  }

  /**
   * Checks Objects are equal by reference.
   *
   * @param o1 the first object
   * @param o2 the second object
   * @return <code>true</code>, if equals by reference, otherwise <code>false</code>
   */
  private static boolean isEqualsByReference(Object o1, Object o2)
  {
    return o1 == o2;
  }

  /**
   * Checks Objects are not equal by reference.
   *
   * @param o1 the first object
   * @param o2 the second object
   * @return <code>false</code>, if equals by reference, otherwise <code>true</code>
   */
  private static boolean notEqualsByReference(Object o1, Object o2)
  {
    return o1 != o2;
  }

  /**
   * Default mode for {@link #isEquals(Object, Object, EqualsMode, Comparator)} - {@link EqualsMode#BOTH}.
   *
   * @see EqualsMode#BOTH
   */
  private static final EqualsMode DEFAULT_EQUALS_MODE = EqualsMode.BOTH;

  /**
   * Enum for different modes usable at {@link #isEquals(Object, Object, EqualsMode, Comparator)} implementing
   * {@link Comparator} indicating equality by <code>0</code>.
   *
   * @see #isEquals(Object, Object, EqualsMode, Comparator)
   * @see Comparator
   * @see Comparator#compare(Object, Object)
   * @author Jens Wothe, jw@bos-bremen.de
   */
  public enum EqualsMode implements Comparator<Object>
  {

    /**
     * Mode for checking Objects are equal: first Object must be equal to second.
     *
     * @see Object#equals(Object)
     */
    FIRST_SECOND((o1, o2) -> o1.equals(o2) ? COMPARE_RESULT_FIRST_EQUAL_TO_SECOND : COMPARE_RESULT_FIRST_LESS_SECOND),
    /**
     * Mode for checking Objects are equal: second Object must be equal to first.
     *
     * @see Object#equals(Object)
     */
    SECOND_FIRST((o1, o2) -> o2.equals(o1) ? COMPARE_RESULT_FIRST_EQUAL_TO_SECOND : COMPARE_RESULT_FIRST_LESS_SECOND),
    /**
     * Mode for checking Objects are equal: at least one Object must be equal to another.
     *
     * @see Object#equals(Object)
     */
    ANYONE((o1, o2) -> o1.equals(o2) || o2.equals(o1) ? COMPARE_RESULT_FIRST_EQUAL_TO_SECOND
      : COMPARE_RESULT_FIRST_LESS_SECOND),
    /**
     * Mode for checking Objects are equal: both Object must be equal to each other.
     *
     * @see Object#equals(Object)
     */
    BOTH((o1, o2) -> o1.equals(o2) && o2.equals(o1) ? COMPARE_RESULT_FIRST_EQUAL_TO_SECOND
      : COMPARE_RESULT_FIRST_LESS_SECOND);

    // comparator
    private Comparator<Object> comparator = null;

    /**
     * Constructor.
     *
     * @param comparator comparator, <code>null</code> not permitted
     */
    private EqualsMode(Comparator<Object> comparator)
    {
      AssertUtil.notNull(comparator, "comparator");
      this.comparator = comparator;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int compare(Object o1, Object o2)
    {
      int result = COMPARE_RESULT_FIRST_LESS_SECOND;
      if (ObjectUtil.notEqualsByReference(o1, o2) && ObjectUtil.notNull(o1) && ObjectUtil.notNull(o2))
      {
        // both Objects are not null, so compare them using comparator instance
        result = this.comparator.compare(o1, o2);
      }
      return result;
    }
  }

}

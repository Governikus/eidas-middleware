/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardbase;

/**
 * Utilities related to {@link NumInfo}.
 *
 * @author Jens Wothe, jw@bos-bremen.de
 */
public final class NumInfoUtil
{

  /**
   * Constructor.
   */
  private NumInfoUtil()
  {
    super();
  }

  /**
   * Get NumInfo for type class.
   *
   * @param <T> type of number & comparable class
   * @param <S> type of number class
   * @param typeClass type class, <code>null</code> not permitted, unknown number class not permitted
   * @return NumInfo
   * @throws IllegalArgumentException if type class <code>null</code> or unknown number class
   */
  @SuppressWarnings("unchecked")
  static <T extends Number & Comparable<T>, S extends T> NumInfo<T> getNumInfo(Class<S> typeClass)
  {
    AssertUtil.notNull(typeClass, "type class");
    for ( NumInfo<?> ni : de.governikus.eumw.poseidas.cardbase.impl.NumInfoImpl.LIST_NUM_INFO )
    {
      if (ni.getNumClass().equals(typeClass))
      {
        return (NumInfo<T>)ni;
      }
    }
    throw new IllegalArgumentException("unknown number type: " + typeClass);
  }

}

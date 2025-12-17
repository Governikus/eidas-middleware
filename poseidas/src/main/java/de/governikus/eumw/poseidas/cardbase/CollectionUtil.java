/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardbase;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;


/**
 * Some convenience functions for Collection, List, Map and Set.
 *
 * @see Collection
 * @see List
 * @see Map
 * @see Set
 * @author Jens Wothe, jw@bos-bremen.de
 */
public final class CollectionUtil
{

  /**
   * Constructor.
   */
  private CollectionUtil()
  {
    super();
  }

  /**
   * Checks Collection is <code>null</code>.
   *
   * @param collection Collection to check
   * @return <code>true</code>, if Collection is <code>null</code>, otherwise <code>false</code>
   * @see #isNullOrEmpty(Collection)
   */
  private static final boolean isNull(Collection<?> collection)
  {
    return collection == null;
  }

  /**
   * Checks Collection is <code>null</code>.
   *
   * @param list list to check
   * @return <code>true</code>, if List is <code>null</code>, otherwise <code>false</code>
   * @see #isEmpty(List)
   * @see #isNullOrEmpty(List)
   * @see #containsNull(List)
   * @see #isNullOrEmptyOrContainsNull(List)
   */
  public static boolean isNull(List<?> list)
  {
    return list == null;
  }

  /**
   * Checks Collection is <code>null</code> or empty.
   *
   * @param collection Collection to check
   * @return <code>true</code>, if Collection is <code>null</code> or empty, otherwise <code>false</code>
   * @see #isNull(Collection)
   */
  public static final boolean isNullOrEmpty(Collection<?> collection)
  {
    return isNull(collection) || collection.isEmpty();
  }

}

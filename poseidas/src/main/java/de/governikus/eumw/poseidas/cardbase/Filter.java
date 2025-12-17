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
 * Generic filter for any filtering purpose as e. g. searching for instance at list or arrays for matching criteria.
 *
 * @param <T> instance used by filtering at {@link #accept(Object)}
 * @author Jens Wothe, jw@bos-bremen.de
 */
public interface Filter<T extends Object>
{

  /**
   * Checks an instance is accepted by filter.
   *
   * @param object object to be checked for acceptance by filter
   * @return <code>true</code> when accepted, otherwise <code>false</code>
   */
  public boolean accept(T object);

  /**
   * Gets Class of filter for casting efforts.
   *
   * @return Class of filter
   * @see Class#cast(Object)
   */
  public Class<T> getFilterClass();

}

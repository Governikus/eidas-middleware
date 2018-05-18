/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardserver.eac.functions;


/**
 * Base interface for instance related to a specified count of APDUs (commands or responses).
 *
 * @author Jens Wothe, jw@bos-bremen.de
 */
public interface APDUCountRestricted
{

  /**
   * Gets minimum count of APDUs (commands or responses).
   * 
   * @return minimum
   */
  public abstract int getMinimumCount();

  /**
   * Gets maximum count of APDUs (commands or responses).
   * 
   * @return maximum
   */
  public abstract int getMaximumCount();

}

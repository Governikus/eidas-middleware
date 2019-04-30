/*
 * Copyright (c) 2019 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.eidserver.convenience.session;

import java.util.Comparator;
import java.util.Map;


/**
 * SessionComparator to compare sessions by there timeout
 *
 * @author Ole Behrens
 */
public class SessionComparator implements Comparator<String>
{

  private Long check;

  private Session latestInvalidSession;

  private String latestInvalidSessionId;

  private final Map<String, Session> map;

  SessionComparator(Map<String, Session> map, Long timeout)
  {
    super();
    this.check = timeout;
    this.map = map;
  }

  /**
   * Get the latest invalid session to be able to optimize the TreeMap
   *
   * @return the latest invalid session from list
   */
  public String getLatestInvalidSessionId()
  {
    return latestInvalidSessionId;
  }

  @Override
  public int compare(String o1, String o2)
  {
    // Key is null
    if (o1 == null)
    {
      throw new IllegalArgumentException("Session identifier is null");
    }
    if (o1.equals(o2))
    {
      return 0;
    }
    // The value to be added
    Session sessionA = map.get(o1);
    // Value to be added must exist
    if (sessionA == null)
    {
      throw new IllegalArgumentException("Session identifier: " + o1 + " is not available");
    }
    // Key to compare must exist
    if (o2 == null)
    {
      return 0;
    }
    // Value to be compared with
    Session sessionB = map.get(o2);
    // There is no value to be compare so put at position 0
    if (sessionB == null)
    {
      return 0;
    }

    // Do not compare Session but the timeout-value
    long validToA = sessionA.getValidTo();
    // If no timeout is set, get current time
    if (check == null)
    {
      check = System.currentTimeMillis();
    }
    // To be able to optimize the TreeMap store the latest session that is invalid
    if (validToA < check)
    {
      if (latestInvalidSession == null || latestInvalidSession.getValidTo() < validToA)
      {
        latestInvalidSession = sessionA;
        latestInvalidSessionId = o1;
      }
    }
    // Timeout from value to be compared
    long validToB = sessionB.getValidTo();
    // Insert before or after
    if (validToA > validToB)
    {
      return 1;
    }
    else
    {
      return -1;
    }
  }
}

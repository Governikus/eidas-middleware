/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.eidasmiddleware;

import static org.junit.Assert.assertTrue;

import java.sql.SQLException;
import java.sql.Timestamp;

import org.junit.Before;
import org.junit.Test;

import de.governikus.eumw.eidasstarterkit.EidasNaturalPersonAttributes;



public class SessionStoreTest
{

  String relayState = "relayState01";

  String reqId = "XXXX-XXXX-XXXX-XXXX";

  String reqDestination = "https://localhost";

  String eidRef = "eid01";

  RequestSession requestSession = null;

  /**
   * Ten seconds in milliseconds
   */
  private static final int TEN_SECONDS = 10000;

  @Before
  public void setUp() throws Exception
  {
    requestSession = new RequestSession(relayState, reqId, reqDestination);
    requestSession.getRequestedAttributes().put(EidasNaturalPersonAttributes.BIRTH_NAME, true);
    requestSession.getRequestedAttributes().put(EidasNaturalPersonAttributes.CURRENT_ADDRESS, false);
  }

  @Test
  public void test() throws ClassNotFoundException, SQLException, Exception
  {

    try (SessionStore store = new SessionStore())
    {
      store.openDBConnection();
      store.setupDb();
      store.insert(requestSession);
      RequestSession compareSession = store.getById(reqId);
      check(compareSession);
      store.update(compareSession.getReqId(), eidRef);
      RequestSession compareSession2 = store.getById(reqId);
      check(compareSession2);
      RequestSession compareSession3 = store.getByEidRef(eidRef);
      check(compareSession3);
      store.cleanUpByTimeStamp(new Timestamp(System.currentTimeMillis() + TEN_SECONDS));
      RequestSession compareSession4 = store.getById(reqId);
      assertTrue(compareSession4 == null);
    }
  }

  public void check(RequestSession compareSession)
  {
    assertTrue(compareSession != null);
    assertTrue(compareSession.getRelayState().equals(relayState));
    assertTrue(compareSession.getReqDestination().equals(reqDestination));
    assertTrue(compareSession.getReqId().equals(reqId));
    assertTrue(compareSession.getRequestedAttributes().size() == 2);
    assertTrue(compareSession.getRequestedAttributes().get(EidasNaturalPersonAttributes.BIRTH_NAME));
    assertTrue(!compareSession.getRequestedAttributes().get(EidasNaturalPersonAttributes.CURRENT_ADDRESS));
  }
}

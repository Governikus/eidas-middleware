package de.governikus.eumw.poseidas.server.eidservice;


import static org.mockito.Mockito.mock;


import java.util.EnumMap;
import java.util.Map;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import de.governikus.panstar.sdk.utils.constant.EIDAttributeName;
import de.governikus.eumw.poseidas.eidserver.convenience.EIDInfoResult;
import de.governikus.eumw.poseidas.eidserver.ecardid.SessionInput;
import de.governikus.eumw.poseidas.eidserver.ecardid.EIDInfoContainer.EIDStatus;
import oasis.names.tc.dss._1_0.core.schema.Result;


class EIDSessionTest
{

  @Test
  void testSession()
  {

    Result result = mock(Result.class);
    SessionInput input = mock(SessionInput.class);
    Map<EIDAttributeName, EIDInfoResult> infoMap = new EnumMap<>(EIDAttributeName.class);

    EIDSession session = new EIDSession("sess-1", "req-1", "provider-1");
    session.setSequenceNumber(42);
    session.setResult(result);
    session.setInfoMap(infoMap);
    session.setSessionInput(input);
    session.setStatus(EIDStatus.VALID);

    // then - basics
    Assertions.assertEquals("sess-1", session.getSessionId());
    Assertions.assertEquals("req-1", session.getRequestId());
    Assertions.assertTrue(session.getCreationTime() > 0);

    // then - prefix logic
    Assertions.assertTrue(session.getLogPrefix().contains("provider-1"));
    Assertions.assertTrue(session.getLogPrefix().contains("req-1"));

    // then - state
    Assertions.assertEquals(42, session.getSequenceNumber());
    Assertions.assertSame(result, session.getResult());
    Assertions.assertSame(infoMap, session.getInfoMap());
    Assertions.assertSame(input, session.getSessionInput());
    Assertions.assertEquals(EIDStatus.VALID, session.getStatus());
  }
}

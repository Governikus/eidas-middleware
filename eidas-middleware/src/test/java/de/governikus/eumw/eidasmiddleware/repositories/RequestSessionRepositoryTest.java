/*
 * Copyright (c) 2022 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.eidasmiddleware.repositories;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import de.governikus.eumw.eidasmiddleware.entities.RequestSession;
import de.governikus.eumw.eidasstarterkit.EidasNaturalPersonAttributes;
import de.governikus.eumw.eidasstarterkit.EidasRequest;
import de.governikus.eumw.eidasstarterkit.person_attributes.EidasPersonAttributes;
import lombok.SneakyThrows;


@ExtendWith(SpringExtension.class)
@ContextConfiguration(classes = RequestSessionTestSetup.class)
class RequestSessionRepositoryTest
{

  private final String relayState = "relayState";

  private final String id = "id";

  private final String destination = "destination";

  private final String issuer = "issuer";

  private final String eidRef = "eidRef";

  private final String providerName = "providerName";

  @Autowired
  RequestSessionRepository requestSessionRepository;

  @Test
  void testGetAndUpdate()
  {
    EidasRequest eidasRequest = mockEidasRequest();

    // Create and save the RequestSession
    RequestSession requestSession = new RequestSession(relayState, eidasRequest, providerName);
    RequestSession savedSession = requestSessionRepository.save(requestSession);
    assertFinalFields(savedSession);
    Instant savedCreationTime = savedSession.getCreationTime();
    Assertions.assertTrue(savedCreationTime.isAfter(Instant.now().minus(1, ChronoUnit.MINUTES)));

    // Get by AuthnRequestID
    Assertions.assertTrue(requestSessionRepository.findById(id).isPresent());

    // Set eidRef
    savedSession.setEidRef(eidRef);
    requestSessionRepository.save(savedSession);

    // Get by eidRef
    Optional<RequestSession> requestSessionByEidRef = requestSessionRepository.findByEidRef(eidRef);
    Assertions.assertTrue(requestSessionByEidRef.isPresent());
    assertFinalFields(requestSessionByEidRef.get());
    Assertions.assertEquals(savedCreationTime.truncatedTo(ChronoUnit.SECONDS),
                            requestSessionByEidRef.get().getCreationTime().truncatedTo(ChronoUnit.SECONDS));
    Assertions.assertEquals(eidRef, requestSessionByEidRef.get().getEidRef());
  }

  @SneakyThrows
  @Test
  void testDelete()
  {
    EidasRequest eidasRequest = mockEidasRequest();

    // Create and save the RequestSession
    RequestSession requestSession = new RequestSession(relayState, eidasRequest, providerName);
    requestSessionRepository.save(requestSession);

    // RequestSession is too young and should not be deleted
    Assertions.assertEquals(1, requestSessionRepository.count());
    requestSessionRepository.removeAllByCreationTimeBefore(Instant.now().minus(1, ChronoUnit.HOURS));
    Assertions.assertEquals(1, requestSessionRepository.count());

    // Wait some seconds and use a shorter reference time
    Thread.sleep(2000);
    Assertions.assertEquals(1, requestSessionRepository.count());
    requestSessionRepository.removeAllByCreationTimeBefore(Instant.now().minus(1, ChronoUnit.SECONDS));
    Assertions.assertEquals(0, requestSessionRepository.count());
  }

  private EidasRequest mockEidasRequest()
  {
    // Test data
    Map<EidasPersonAttributes, Boolean> requestedAttributes = new HashMap<>();
    requestedAttributes.put(EidasNaturalPersonAttributes.BIRTH_NAME, true);
    requestedAttributes.put(EidasNaturalPersonAttributes.PERSON_IDENTIFIER, false);

    // Mock the EidasRequest
    EidasRequest eidasRequest = Mockito.mock(EidasRequest.class);
    Mockito.when(eidasRequest.getId()).thenReturn(id);
    Mockito.when(eidasRequest.getDestination()).thenReturn(destination);
    Mockito.when(eidasRequest.getIssuer()).thenReturn(issuer);
    Mockito.when(eidasRequest.getRequestedAttributes()).thenReturn(requestedAttributes);
    return eidasRequest;
  }

  private void assertFinalFields(RequestSession savedSession)
  {
    Assertions.assertNotNull(savedSession);
    Assertions.assertEquals(relayState, savedSession.getRelayState());
    Assertions.assertEquals(id, savedSession.getReqId());
    Assertions.assertEquals(destination, savedSession.getReqDestination());
    Assertions.assertEquals(issuer, savedSession.getReqProviderEntityId());
    Assertions.assertEquals(providerName, savedSession.getReqProviderName());
    Assertions.assertEquals(2, savedSession.getRequestedAttributes().size());
    Assertions.assertEquals(true,
                            savedSession.getRequestedAttributes()
                                        .get(EidasNaturalPersonAttributes.BIRTH_NAME.getName()));
    Assertions.assertEquals(false,
                            savedSession.getRequestedAttributes()
                                        .get(EidasNaturalPersonAttributes.PERSON_IDENTIFIER.getName()));
  }
}

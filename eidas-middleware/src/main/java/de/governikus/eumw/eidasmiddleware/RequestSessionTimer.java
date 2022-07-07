/*
 * Copyright (c) 2022 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.eidasmiddleware;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.concurrent.TimeUnit;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import de.governikus.eumw.eidasmiddleware.repositories.RequestSessionRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;


@Component
@RequiredArgsConstructor
@Slf4j
public class RequestSessionTimer
{

  private final RequestSessionRepository requestSessionRepository;

  @Scheduled(fixedRate = 1, timeUnit = TimeUnit.HOURS)
  public void deleteOldRequestSessions()
  {
    log.debug("Deleting old request sessions");
    long deletedSessions = requestSessionRepository.removeAllByCreationTimeBefore(Instant.now()
                                                                                         .minus(24, ChronoUnit.HOURS));
    log.debug("Deleted {} old request sessions", deletedSessions);
  }
}

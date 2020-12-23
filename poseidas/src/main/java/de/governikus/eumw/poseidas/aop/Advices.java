/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.aop;

import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.stereotype.Component;

import lombok.extern.slf4j.Slf4j;


@Aspect
@Component
@Slf4j
public class Advices
{

  @Around("de.governikus.eumw.poseidas.aop.JoinPoints.applicationTimerLogging()")
  public Object logTimerExecutionInfo(ProceedingJoinPoint proceedingJoinPoint) throws Throwable
  {
    long startTime = System.currentTimeMillis();
    log.info("Starting timer {}", proceedingJoinPoint.toShortString());
    Object object = proceedingJoinPoint.proceed();
    long endTime = System.currentTimeMillis();
    log.info("Execution of timer {} finished after {} ms", proceedingJoinPoint.toShortString(), endTime - startTime);
    return object;
  }

  @Around("de.governikus.eumw.poseidas.aop.JoinPoints.backgroundTimerLogging()")
  public Object logTimerExecutionDebug(ProceedingJoinPoint proceedingJoinPoint) throws Throwable
  {
    long startTime = System.currentTimeMillis();
    log.debug("Starting timer {}", proceedingJoinPoint.toShortString());
    Object object = proceedingJoinPoint.proceed();
    long endTime = System.currentTimeMillis();
    log.debug("Execution of timer {} finished after {} ms", proceedingJoinPoint.toShortString(), endTime - startTime);
    return object;
  }
}

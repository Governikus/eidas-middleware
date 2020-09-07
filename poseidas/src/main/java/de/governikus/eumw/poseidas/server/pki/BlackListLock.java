/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.pki;

import java.util.concurrent.locks.ReentrantLock;

import lombok.Getter;


/**
 * Add locking mechanism for black list updates to prevent parallel black list updates executed manually and
 * by timer
 */
final class BlackListLock
{

  @Getter
  private static final BlackListLock INSTANCE = new BlackListLock();

  @Getter
  private ReentrantLock blackListUpdateLock;

  private BlackListLock()
  {
    blackListUpdateLock = new ReentrantLock();
  }

}

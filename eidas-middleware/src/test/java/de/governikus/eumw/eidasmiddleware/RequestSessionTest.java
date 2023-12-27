/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.eidasmiddleware;

import java.util.Collections;

import org.junit.jupiter.api.BeforeAll;
import org.mockito.Mockito;

import de.governikus.eumw.eidasstarterkit.EidasRequest;


class RequestSessionTest
{

  private static EidasRequest eidasRequest;

  @BeforeAll
  public static void beforeAll()
  {
    eidasRequest = Mockito.mock(EidasRequest.class);
    Mockito.when(eidasRequest.getId()).thenReturn("reqId");
    Mockito.when(eidasRequest.getDestination()).thenReturn("destination");
    Mockito.when(eidasRequest.getIssuer()).thenReturn("issuer");
    Mockito.when(eidasRequest.getRequestedAttributes()).thenReturn(Collections.emptyMap());
  }

}

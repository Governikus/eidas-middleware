/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.eidasmiddleware.projectconfig;

import org.junit.jupiter.api.Test;
import org.springframework.stereotype.Controller;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.GetMapping;

import de.governikus.eumw.eidascommon.ContextPaths;
import de.governikus.eumw.eidasmiddleware.controller.RequestReceiver;


/**
 * Test the port filter
 */
class PortFilterTest
{

  @Test
  void testPortsAndPaths() throws Exception
  {
    MockMvc requestReceiver = MockMvcBuilders.standaloneSetup(new RequestReceiver(null, null, null))
                                             .addFilters(new PortFilter(8443, 10000))
                                             .build();
    // eidas request on port 8443
    requestReceiver.perform(MockMvcRequestBuilders.get(ContextPaths.EIDAS_CONTEXT_PATH
                                                       + ContextPaths.REQUEST_RECEIVER)
                                                  .servletPath(ContextPaths.EIDAS_CONTEXT_PATH
                                                               + ContextPaths.REQUEST_RECEIVER)
                                                  .with(mockHttpServletRequest -> {
                                                    mockHttpServletRequest.setLocalPort(8443);
                                                    return mockHttpServletRequest;
                                                  }))
                   .andExpect(MockMvcResultMatchers.status().isBadRequest());

    // eidas request on port 10000
    requestReceiver.perform(MockMvcRequestBuilders.get(ContextPaths.EIDAS_CONTEXT_PATH
                                                       + ContextPaths.REQUEST_RECEIVER)
                                                  .servletPath(ContextPaths.EIDAS_CONTEXT_PATH
                                                               + ContextPaths.REQUEST_RECEIVER)
                                                  .with(mockHttpServletRequest -> {
                                                    mockHttpServletRequest.setLocalPort(10000);
                                                    return mockHttpServletRequest;
                                                  }))
                   .andExpect(MockMvcResultMatchers.status().isForbidden());

    requestReceiver = MockMvcBuilders.standaloneSetup(new MockAdminController())
                                     .addFilters(new PortFilter(8443, 10000))
                                     .build();

    // admin request on port 8443
    requestReceiver.perform(MockMvcRequestBuilders.get(ContextPaths.ADMIN_CONTEXT_PATH + ContextPaths.LOGIN)
                                                  .servletPath(ContextPaths.ADMIN_CONTEXT_PATH
                                                               + ContextPaths.LOGIN)
                                                  .with(mockHttpServletRequest -> {
                                                    mockHttpServletRequest.setLocalPort(8443);
                                                    return mockHttpServletRequest;
                                                  }))
                   .andExpect(MockMvcResultMatchers.status().isForbidden());

    // admin request on port 10000
    requestReceiver.perform(MockMvcRequestBuilders.get(ContextPaths.ADMIN_CONTEXT_PATH + ContextPaths.LOGIN)
                                                  .servletPath(ContextPaths.ADMIN_CONTEXT_PATH
                                                               + ContextPaths.LOGIN)
                                                  .with(mockHttpServletRequest -> {
                                                    mockHttpServletRequest.setLocalPort(10000);
                                                    return mockHttpServletRequest;
                                                  }))
                   .andExpect(MockMvcResultMatchers.status().isOk());
  }

  /**
   * Mock class because other admin interface controllers are not available
   */
  @Controller
  private static class MockAdminController
  {

    @GetMapping(ContextPaths.ADMIN_CONTEXT_PATH + ContextPaths.LOGIN)
    public String login()
    {
      return "logged in";
    }
  }
}

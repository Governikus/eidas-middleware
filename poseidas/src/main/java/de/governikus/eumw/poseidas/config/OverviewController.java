/*
 * Copyright (c) 2022 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.config;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletResponse;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import de.governikus.eumw.config.EidasMiddlewareConfig;
import de.governikus.eumw.eidascommon.ContextPaths;
import de.governikus.eumw.poseidas.config.model.ServiceProviderDetails;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationService;
import de.governikus.eumw.poseidas.server.pki.PermissionDataHandlingMBean;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;


/**
 * This controller shows the overview page
 *
 * @author bpr
 */
@Slf4j
@Controller
@RequiredArgsConstructor
@RequestMapping(ContextPaths.ADMIN_CONTEXT_PATH)
public class OverviewController
{

  private final PermissionDataHandlingMBean data;

  private final ConfigurationService configurationService;

  /**
   * The index route redirects to /dashboard
   */
  @GetMapping("")
  public void index(HttpServletResponse response) throws IOException
  {
    response.sendRedirect(ContextPaths.ADMIN_CONTEXT_PATH + ContextPaths.DASHBOARD);
  }

  /**
   * This route represents the dashboard view
   */
  @GetMapping("dashboard")
  public String dashboard(Model model)
  {
    Map<String, ServiceProviderDetails> cvcList = createCvcList();
    if (cvcList.isEmpty())
    {
      model.addAttribute("noProviders", "There are no service providers configured");
    }
    else
    {
      model.addAttribute("entities", cvcList.values());
    }
    return "pages/dashboard";
  }

  private Map<String, ServiceProviderDetails> createCvcList()
  {
    Map<String, ServiceProviderDetails> cvcList = new HashMap<>();
    configurationService.getConfiguration()
                        .map(EidasMiddlewareConfig::getEidConfiguration)
                        .map(EidasMiddlewareConfig.EidConfiguration::getServiceProvider)
                        .stream()
                        .parallel()
                        .flatMap(List::stream)
                        .forEach(serviceProviderType -> cvcList.put(serviceProviderType.getName(),
                                                                    new ServiceProviderDetails(serviceProviderType,
                                                                                               data.getPermissionDataInfo(serviceProviderType.getCVCRefID(),
                                                                                                                          false),
                                                                                               null)));
    return cvcList;
  }
}

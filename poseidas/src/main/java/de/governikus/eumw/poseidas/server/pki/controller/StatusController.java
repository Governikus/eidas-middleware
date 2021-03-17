/*
 * Copyright (c) 2021 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.pki.controller;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import de.governikus.eumw.eidascommon.ContextPaths;
import de.governikus.eumw.poseidas.server.idprovider.config.CvcTlsCheck;
import de.governikus.eumw.poseidas.server.pki.PermissionDataHandlingMBean;
import de.governikus.eumw.poseidas.server.pki.RequestSignerCertificateService;
import de.governikus.eumw.poseidas.server.pki.TerminalPermissionAO;
import de.governikus.eumw.poseidas.server.pki.model.GlobalResultModel;
import de.governikus.eumw.poseidas.server.pki.model.ServiceProviderResultModel;
import lombok.extern.slf4j.Slf4j;


/**
 * This controller provides the status page for the admin interface
 *
 * @author bpr
 */
@Slf4j
@Controller
@RequestMapping(ContextPaths.ADMIN_CONTEXT_PATH)
public class StatusController
{

  private final CvcTlsCheck cvcTlsCheck;

  private final TerminalPermissionAO facade;

  private final PermissionDataHandlingMBean permissionDataHandling;

  private final RequestSignerCertificateService rscService;

  public StatusController(CvcTlsCheck cvcTlsCheck,
                          TerminalPermissionAO facade,
                          PermissionDataHandlingMBean permissionDataHandling,
                          RequestSignerCertificateService rscService)
  {
    this.cvcTlsCheck = cvcTlsCheck;
    this.facade = facade;
    this.permissionDataHandling = permissionDataHandling;
    this.rscService = rscService;
  }

  /**
   * This route shows the status view
   */
  @GetMapping("status")
  public String status(Model model)
  {
    CvcTlsCheck.CvcTlsCheckResult cvcTlsCheckResult = cvcTlsCheck.check();

    GlobalResultModel globalResultModel = new GlobalResultModel(cvcTlsCheckResult);
    model.addAttribute(globalResultModel);

    Map<String, ServiceProviderResultModel> serviceProviderResultModelMap = new HashMap<>();
    for ( Map.Entry<String, CvcTlsCheck.CvcCheckResults> serviceProvider : cvcTlsCheckResult.getProviderCvcChecks()
                                                                                            .entrySet() )
    {
      serviceProviderResultModelMap.put(serviceProvider.getKey(),
                                        new ServiceProviderResultModel(serviceProvider.getKey(),
                                                                       serviceProvider.getValue(), facade,
                                                                       permissionDataHandling, rscService));
    }

    SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault());
    model.addAttribute("result", cvcTlsCheckResult);
    model.addAttribute("globalResultModel", globalResultModel);
    model.addAttribute("serviceProviderResultModelMap", serviceProviderResultModelMap);
    model.addAttribute("lastCheck", formatter.format(new Date()));
    return "status";
  }
}

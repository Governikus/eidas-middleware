/*
 * Copyright (c) 2021 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.config;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import de.governikus.eumw.config.EidasMiddlewareConfig;
import de.governikus.eumw.config.ServiceProviderType;
import de.governikus.eumw.eidascommon.ContextPaths;
import de.governikus.eumw.poseidas.config.model.GlobalResultModel;
import de.governikus.eumw.poseidas.config.model.ServiceProviderStatus;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationService;
import de.governikus.eumw.poseidas.server.idprovider.config.CvcTlsCheck;
import de.governikus.eumw.poseidas.server.idprovider.config.CvcTlsCheck.CvcTlsCheckResult;
import de.governikus.eumw.poseidas.server.pki.ServiceProviderStatusService;
import de.governikus.eumw.utils.key.exceptions.UnsupportedECCertificateException;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;


/**
 * This controller provides the status page for the admin interface
 *
 * @author bpr
 */
@Slf4j
@Controller
@RequestMapping(ContextPaths.ADMIN_CONTEXT_PATH)
@AllArgsConstructor
public class DashboardController
{

  private final CvcTlsCheck cvcTlsCheck;

  private final ConfigurationService configurationService;

  private final ServiceProviderStatusService serviceProviderStatusService;

  /**
   * This route shows the status view
   */
  @GetMapping(ContextPaths.DASHBOARD)
  public String status(Model model)
  {

    // TLS EC only performed on startup, not needed here
    Optional<CvcTlsCheckResult> cvcTlsCheckResult;
    try
    {
      cvcTlsCheckResult = cvcTlsCheck.check(false);
      if (cvcTlsCheckResult.isEmpty())
      {
        model.addAttribute("msg", "No status available because configuration is not valid.");
        model.addAttribute("valuesAvailable", false);
        return "pages/status";
      }
      GlobalResultModel globalResultModel = new GlobalResultModel(cvcTlsCheckResult.get());
      model.addAttribute(globalResultModel);

      Map<String, ServiceProviderStatus> serviceProviderResultModelMap;
      serviceProviderResultModelMap = configurationService.getConfiguration()
                                                          .map(EidasMiddlewareConfig::getEidConfiguration)
                                                          .map(EidasMiddlewareConfig.EidConfiguration::getServiceProvider)
                                                          .stream()
                                                          .flatMap(List::stream)
                                                          .collect(Collectors.toMap(ServiceProviderType::getName,
                                                                                    serviceProviderStatusService::getServiceProviderStatus));
      model.addAttribute("valuesAvailable", true);
      model.addAttribute("globalResultModel", globalResultModel);
      model.addAttribute("serviceProviderResultModelMap", serviceProviderResultModelMap);
      SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault());
      model.addAttribute("lastCheck", formatter.format(new Date()));
      return "pages/status";
    }
    catch (UnsupportedECCertificateException e)
    {
      // Should never be thrown here
      log.error(e.getMessage());
    }
    return StringUtils.EMPTY;
  }
}

/*
 * Copyright (c) 2022 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.config;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.boot.info.BuildProperties;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

import de.governikus.eumw.config.EidasMiddlewareConfig;
import de.governikus.eumw.config.ServiceProviderType;
import de.governikus.eumw.eidascommon.ContextPaths;
import de.governikus.eumw.poseidas.config.model.ServiceProviderStatus;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationService;
import de.governikus.eumw.poseidas.server.pki.ServiceProviderStatusService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;


@Slf4j
@Controller
@RequestMapping(ContextPaths.ADMIN_CONTEXT_PATH + "/support")
@RequiredArgsConstructor
public class SupportController
{

  private final ConfigurationService configurationService;

  private final ServiceProviderStatusService serviceProviderStatusService;

  private final BuildProperties buildProperties;


  @GetMapping
  public ModelAndView showSupportPage()
  {
    ModelAndView support = new ModelAndView("pages/support");
    support.addObject("mailtoLink", getMailto());
    support.addObject("mailText", getMailText());
    return support;

  }


  private String getMailto()
  {
    String recipient = "eidas-middleware@governikus.de";

    String subject = "eIDAS Middleware Support Request from ";
    subject += configurationService.getConfiguration()
                                   .map(EidasMiddlewareConfig::getEidasConfiguration)
                                   .map(EidasMiddlewareConfig.EidasConfiguration::getCountryCode)
                                   .orElse("Unknown");
    subject = encodeURIComponent(subject);
    String body = getMailText();
    body = encodeURIComponent(body);
    return String.format("mailto:%s?subject=%s&body=%s", recipient, subject, body);
  }

  private String getMailText()
  {
    Map<String, ServiceProviderStatus> serviceProviderStatusMap;
    serviceProviderStatusMap = configurationService.getConfiguration()
                                                   .map(EidasMiddlewareConfig::getEidConfiguration)
                                                   .map(EidasMiddlewareConfig.EidConfiguration::getServiceProvider)
                                                   .stream()
                                                   .flatMap(List::stream)
                                                   .collect(Collectors.toMap(ServiceProviderType::getName,
                                                                             serviceProviderStatusService::getServiceProviderStatus));

    StringBuilder bodyBuilder = new StringBuilder("Dear Governikus support team,\n\n");
    bodyBuilder.append("<Please describe your problems here>\n\n");
    bodyBuilder.append("<Fill in eIDAS node version you are using>\n\n");
    bodyBuilder.append("<Do not forget to attach the eIDAS Middleware XML configuration to this mail>\n\n");
    bodyBuilder.append("System information for this eIDAS Middleware:\n");
    bodyBuilder.append("Version: ").append(buildProperties.getVersion()).append("\n");
    bodyBuilder.append("Number of configured service providers: ").append(serviceProviderStatusMap.size()).append("\n");
    for ( Map.Entry<String, ServiceProviderStatus> serviceProvider : serviceProviderStatusMap.entrySet() )
    {
      ServiceProviderStatus serviceProviderStatus = serviceProvider.getValue();
      bodyBuilder.append("ServiceProviderID: ").append(serviceProvider.getKey()).append("\n");
      bodyBuilder.append("\t CVC is present: ").append(serviceProviderStatus.isCvcPresent()).append("\n");
      if (serviceProviderStatus.isCvcPresent())
      {
        bodyBuilder.append("\t CVC is valid: ").append(serviceProviderStatus.isCvcValidity()).append("\n");
        bodyBuilder.append("\t CVC is valid until: ")
                   .append(serviceProviderStatus.getCvcValidUntil().toString())
                   .append("\n");
        bodyBuilder.append("\t URL from CVC and configuration match: ")
                   .append(serviceProviderStatus.isCvcUrlMatch())
                   .append("\n");
        bodyBuilder.append("\t TLS Certificate is linked in CVC: ")
                   .append(serviceProviderStatus.isCvcTLSLinkStatus())
                   .append("\n");
      }
      bodyBuilder.append("\t RSC is present: ")
                 .append(serviceProviderStatus.getRscCurrentValidUntil() != null)
                 .append("\n");
      if (serviceProviderStatus.getRscCurrentValidUntil() != null)
      {
        bodyBuilder.append("\t RSC is valid until: ")
                   .append(serviceProviderStatus.getRscCurrentValidUntil().toString())
                   .append("\n");
      }
      bodyBuilder.append("\t Pending RSC is present: ")
                 .append(serviceProviderStatus.isRscPendingPresent())
                 .append("\n");
    }
    return bodyBuilder.toString();
  }

  static String encodeURIComponent(String component)
  {
    String result;
    result = URLEncoder.encode(component, StandardCharsets.UTF_8)
                       .replaceAll("\\%28", "(")
                       .replaceAll("\\%29", ")")
                       .replaceAll("\\+", "%20")
                       .replaceAll("\\%27", "'")
                       .replaceAll("\\%21", "!")
                       .replaceAll("\\%7E", "~");

    return result;
  }

}

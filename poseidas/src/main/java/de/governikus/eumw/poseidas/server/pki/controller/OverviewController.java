/*
 * Copyright (c) 2021 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.pki.controller;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletResponse;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import de.governikus.eumw.eidascommon.ContextPaths;
import de.governikus.eumw.poseidas.server.exception.MetadataDownloadException;
import de.governikus.eumw.poseidas.server.idprovider.config.CoreConfigurationDto;
import de.governikus.eumw.poseidas.server.idprovider.config.CvcTlsCheck;
import de.governikus.eumw.poseidas.server.idprovider.config.PoseidasConfigurator;
import de.governikus.eumw.poseidas.server.idprovider.config.ServiceProviderDto;
import de.governikus.eumw.poseidas.server.pki.PermissionDataHandlingMBean;
import de.governikus.eumw.poseidas.server.pki.RequestSignerCertificateService;
import de.governikus.eumw.poseidas.server.pki.TerminalPermissionAO;
import de.governikus.eumw.poseidas.server.pki.model.CVCInfoBean;
import de.governikus.eumw.poseidas.service.MetadataService;
import lombok.extern.slf4j.Slf4j;


/**
 * This controller shows the overview page
 *
 * @author bpr
 */
@Slf4j
@Controller
@RequestMapping(ContextPaths.ADMIN_CONTEXT_PATH)
public class OverviewController
{

  private final Map<String, CVCInfoBean> cvcList;

  private final MetadataService metadataService;

  public OverviewController(PermissionDataHandlingMBean data,
                            MetadataService metadataService,
                            CvcTlsCheck cvcTlsCheck,
                            TerminalPermissionAO facade,
                            RequestSignerCertificateService rscService)
  {
    cvcList = new HashMap<>();
    this.metadataService = metadataService;
    CoreConfigurationDto config = PoseidasConfigurator.getInstance().getCurrentConfig();
    for ( ServiceProviderDto entry : config.getServiceProvider().values() )
    {
      if (entry.getEpaConnectorConfiguration() == null)
      {
        continue;
      }
      cvcList.put(entry.getEntityID(), new CVCInfoBean(entry, data, cvcTlsCheck, facade, rscService));
    }
  }

  public String getMailto(Map.Entry<String, CvcTlsCheck.CvcCheckResults> entry)
  {
    String recipient = "eidas-middleware@governikus.de";
    String subject = encodeURIComponent("TLS CVC subject");
    String body = encodeURIComponent("Lorem ipsum..." + entry.getKey());
    return String.format("mailto:%s?subject=%s&body=%s", recipient, subject, body);
  }

  private String encodeURIComponent(String component)
  {
    String result;
    try
    {
      result = URLEncoder.encode(component, "UTF-8")
                         .replaceAll("\\%28", "(")
                         .replaceAll("\\%29", ")")
                         .replaceAll("\\+", "%20")
                         .replaceAll("\\%27", "'")
                         .replaceAll("\\%21", "!")
                         .replaceAll("\\%7E", "~");
    }
    catch (UnsupportedEncodingException e)
    {
      log.debug("Failed to encode URI for mailto: href", e);
      result = component;
    }

    return result;
  }

  /**
   * The index route redirects to /list
   */
  @GetMapping("")
  public void index(HttpServletResponse response) throws IOException
  {
    response.sendRedirect(ContextPaths.ADMIN_CONTEXT_PATH + "/list");
  }

  @GetMapping("login")
  public String login()
  {
    return "login";
  }

  /**
   * This route represents the list view
   */
  @GetMapping("list")
  public String list(Model model)
  {
    cvcList.values().forEach(CVCInfoBean::fetchInfo);
    model.addAttribute("entities", cvcList.values());
    return "list";
  }

  /**
   * This route performs the download of the middleware metadata as an xml file.
   *
   * @return ResponseEntity with the metadata as a byte stream
   */
  @GetMapping(value = "/download", produces = MediaType.APPLICATION_OCTET_STREAM_VALUE)
  public ResponseEntity<byte[]> downloadMetadata() throws MetadataDownloadException
  {
    byte[] metadataArray = metadataService.getMetadata();
    if (metadataArray.length != 0)
    {
      return ResponseEntity.ok()
                           .header("Content-Disposition", "attachment; filename=Metadata.xml")
                           .contentType(MediaType.APPLICATION_OCTET_STREAM)
                           .body(metadataArray);
    }
    log.error("No Metadata were created. Can not download metadata.");
    throw new MetadataDownloadException();
  }

  /**
   * This {@link ExceptionHandler} handles the {@link MetadataDownloadException}. In case of exception the client is
   * returned to a html site where an error message will be displayed.
   *
   * @param model Model with the information to be displayed
   * @return String as html site
   */
  @ExceptionHandler(MetadataDownloadException.class)
  public String handleMetadataDownloadException(Model model)
  {
    model.addAttribute("errorMessage", "Can not download Metadata. Please check your log and your configuration.");
    return list(model);
  }
}

/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.pki.controller;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

import javax.servlet.http.HttpServletResponse;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import de.governikus.eumw.eidascommon.ContextPaths;
import de.governikus.eumw.poseidas.gov2server.constants.admin.ManagementMessage;
import de.governikus.eumw.poseidas.server.exception.MetadataDownloadException;
import de.governikus.eumw.poseidas.server.idprovider.config.CoreConfigurationDto;
import de.governikus.eumw.poseidas.server.idprovider.config.CvcTlsCheck;
import de.governikus.eumw.poseidas.server.idprovider.config.PoseidasConfigurator;
import de.governikus.eumw.poseidas.server.idprovider.config.ServiceProviderDto;
import de.governikus.eumw.poseidas.server.pki.PermissionDataHandling;
import de.governikus.eumw.poseidas.server.pki.PermissionDataHandlingMBean;
import de.governikus.eumw.poseidas.server.pki.model.CVCInfoBean;
import de.governikus.eumw.poseidas.server.pki.model.CVCRequestModel;
import de.governikus.eumw.poseidas.service.MetadataService;
import lombok.extern.slf4j.Slf4j;


/**
 * This controller provides the different routes for listing the entities and viewing the details page for a
 * single entity.
 *
 * @author bpr
 */
@Slf4j
@Controller
@RequestMapping(ContextPaths.ADMIN_CONTEXT_PATH)
public class CVCController
{

  /**
   * This string represents the OK {@link ManagementMessage}
   */
  private static final String CO_MSG_OK_OK = "CO.msg.ok.ok";

  private final Map<String, CVCInfoBean> cvcList;

  private final MetadataService metadataService;

  private final CvcTlsCheck cvcTlsCheck;

  /**
   * On startup, create a hashmap containing the entityID and the corresponding {@link CVCInfoBean} object
   *
   * @param data the reference to the {@link PermissionDataHandling}
   */
  public CVCController(PermissionDataHandlingMBean data,
                       MetadataService metadataService,
                       CvcTlsCheck cvcTlsCheck)
  {
    cvcList = new HashMap<>();
    this.metadataService = metadataService;
    this.cvcTlsCheck = cvcTlsCheck;
    CoreConfigurationDto config = PoseidasConfigurator.getInstance().getCurrentConfig();
    for ( ServiceProviderDto entry : config.getServiceProvider().values() )
    {
      if (entry.getEpaConnectorConfiguration() == null)
      {
        continue;
      }
      cvcList.put(entry.getEntityID(), new CVCInfoBean(entry, data));
    }
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
    model.addAttribute("entities", cvcList.values());

    return "list";
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
    String result = null;
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
   * This route represents the list view
   */
  @GetMapping("status")
  public String status(Model model)
  {
    CvcTlsCheck.CvcTlsCheckResult cvcTlsCheckResult = cvcTlsCheck.check();
    SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault());
    model.addAttribute("result", cvcTlsCheckResult);
    model.addAttribute("lastCheck", formatter.format(new Date()));
    return "status";
  }

  /**
   * This route represents the details view for the given entityID
   */
  @GetMapping("details/{entityID}")
  public String details(@PathVariable String entityID, Model model, HttpServletResponse response)
    throws IOException
  {
    if (entityID == null || cvcList.get(entityID) == null)
    {
      response.sendError(404, "Entity not found");
      return null;
    }
    cvcList.get(entityID).fetchInfo();
    model.addAttribute("entity", cvcList.get(entityID));
    model.addAttribute("entityID", entityID);
    model.addAttribute("form", new CVCRequestModel());
    return "details";
  }

  /**
   * This route performs the connection check to the DVCA
   */
  @PostMapping("details/{entityID}/check")
  public String check(@PathVariable String entityID, Model model)
  {
    model.addAttribute("entity", cvcList.get(entityID));
    model.addAttribute("entityID", entityID);
    model.addAttribute("form", new CVCRequestModel());

    String result = cvcList.get(entityID).checkReadyForFirstRequest();
    if (CO_MSG_OK_OK.equals(result))
    {
      model.addAttribute("success", true);
      model.addAttribute("resultMessage", "Connection check succeeded");
    }
    else
    {
      model.addAttribute("error", true);
      model.addAttribute("resultMessage", "Connection check failed");
    }
    return "details";
  }

  /**
   * This route peforms the initial certificate request
   */
  @PostMapping("details/{entityID}/initialRequest")
  public String initialRequest(@PathVariable String entityID,
                               Model model,
                               @ModelAttribute CVCRequestModel form)
  {
    model.addAttribute("entityID", entityID);
    model.addAttribute("form", form);

    cvcList.get(entityID).setCountryCode(form.getCountryCode());
    cvcList.get(entityID).setChrMnemonic(form.getCHRMnemonic());
    cvcList.get(entityID).setSequenceNumber(form.getSequenceNumber());

    String result = cvcList.get(entityID).initRequest();
    if (CO_MSG_OK_OK.equals(result))
    {
      model.addAttribute("success", true);
      model.addAttribute("resultMessage", "Initial request succeeded");
    }
    else
    {
      model.addAttribute("error", true);
      model.addAttribute("resultMessage", "Initial request failed");
    }

    cvcList.get(entityID).fetchInfo();
    model.addAttribute("entity", cvcList.get(entityID));

    return "details";
  }

  /**
   * This route performs the renewal of the black list
   */
  @PostMapping("details/{entityID}/renewBlackList")
  public String renewBlackList(@PathVariable String entityID, Model model)
  {
    model.addAttribute("entity", cvcList.get(entityID));
    model.addAttribute("entityID", entityID);
    model.addAttribute("form", new CVCRequestModel());

    String result = cvcList.get(entityID).renewBlackList();
    if (CO_MSG_OK_OK.equals(result))
    {
      model.addAttribute("success", true);
      model.addAttribute("resultMessage", "Renew black list succeeded");
    }
    else
    {
      model.addAttribute("error", true);
      model.addAttribute("resultMessage", "Renew black list failed");
    }
    return "details";
  }

  /**
   * This route performs the renewal of the master defect list
   */
  @PostMapping("details/{entityID}/renewMasterDefectList")
  public String renewMasterDefectList(@PathVariable String entityID, Model model)
  {
    model.addAttribute("entity", cvcList.get(entityID));
    model.addAttribute("entityID", entityID);
    model.addAttribute("form", new CVCRequestModel());

    String result = cvcList.get(entityID).renewMasterAndDefectList();
    if (CO_MSG_OK_OK.equals(result))
    {
      model.addAttribute("success", true);
      model.addAttribute("resultMessage", "Renew master and defect list succeeded");
    }
    else
    {
      model.addAttribute("error", true);
      model.addAttribute("resultMessage", "Renew master and defect list failed");
    }
    return "details";
  }

  /**
   * This route performs the renewal CVC
   */
  @PostMapping("/details/{entityID}/renewCVC")
  public String renewCVC(@PathVariable String entityID, Model model)
  {
    model.addAttribute("entityID", entityID);
    model.addAttribute("form", new CVCRequestModel());

    String result = cvcList.get(entityID).triggerCertRenewal();
    if (CO_MSG_OK_OK.equals(result))
    {
      model.addAttribute("success", true);
      model.addAttribute("resultMessage", "Renew CVC succeeded");
    }
    else
    {
      model.addAttribute("error", true);
      model.addAttribute("resultMessage", "Renew CVC failed");
    }
    cvcList.get(entityID).fetchInfo();
    model.addAttribute("entity", cvcList.get(entityID));
    return "details";
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
   * This {@link ExceptionHandler} handles the {@link MetadataDownloadException}. In case of exception the
   * client is returned to a html site where an error message will be displayed.
   *
   * @param model Model with the information to be displayed
   * @return String as html site
   */
  @ExceptionHandler(MetadataDownloadException.class)
  public String handleMetadataDownloadException(Model model)
  {
    model.addAttribute("errorMessage",
                       "Can not download Metadata. Please check your log and your configuration.");
    return list(model);
  }
}

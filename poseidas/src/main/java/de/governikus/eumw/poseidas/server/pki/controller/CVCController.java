/*
 * Copyright (c) 2019 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.pki.controller;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletResponse;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import de.governikus.eumw.eidascommon.ContextPaths;
import de.governikus.eumw.poseidas.gov2server.constants.admin.ManagementMessage;
import de.governikus.eumw.poseidas.server.idprovider.config.CoreConfigurationDto;
import de.governikus.eumw.poseidas.server.idprovider.config.PoseidasConfigurator;
import de.governikus.eumw.poseidas.server.idprovider.config.ServiceProviderDto;
import de.governikus.eumw.poseidas.server.pki.PermissionDataHandling;
import de.governikus.eumw.poseidas.server.pki.PermissionDataHandlingMBean;
import de.governikus.eumw.poseidas.server.pki.model.CVCInfoBean;
import de.governikus.eumw.poseidas.server.pki.model.CVCRequestModel;


/**
 * This controller provides the different routes for listing the entities and viewing the details page for a
 * single entity.
 *
 * @author bpr
 */
@Controller
@RequestMapping(ContextPaths.ADMIN_CONTEXT_PATH)
public class CVCController
{

  /**
   * This string represents the OK {@link ManagementMessage}
   */
  private static final String CO_MSG_OK_OK = "CO.msg.ok.ok";

  private final Map<String, CVCInfoBean> cvcList;

  /**
   * On startup, create a hashmap containing the entityID and the corresponding {@link CVCInfoBean} object
   *
   * @param data the reference to the {@link PermissionDataHandling}
   */
  public CVCController(PermissionDataHandlingMBean data)
  {
    cvcList = new HashMap<>();
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

}

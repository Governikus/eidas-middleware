/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.pki.controller;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
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
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import de.governikus.eumw.eidascommon.ContextPaths;
import de.governikus.eumw.poseidas.gov2server.constants.admin.ManagementMessage;
import de.governikus.eumw.poseidas.server.exception.RequestSignerDownloadException;
import de.governikus.eumw.poseidas.server.idprovider.config.CoreConfigurationDto;
import de.governikus.eumw.poseidas.server.idprovider.config.CvcTlsCheck;
import de.governikus.eumw.poseidas.server.idprovider.config.PoseidasConfigurator;
import de.governikus.eumw.poseidas.server.idprovider.config.ServiceProviderDto;
import de.governikus.eumw.poseidas.server.pki.PermissionDataHandling;
import de.governikus.eumw.poseidas.server.pki.PermissionDataHandlingMBean;
import de.governikus.eumw.poseidas.server.pki.RequestSignerCertificateService;
import de.governikus.eumw.poseidas.server.pki.RequestSignerCertificateServiceImpl;
import de.governikus.eumw.poseidas.server.pki.TerminalPermissionAO;
import de.governikus.eumw.poseidas.server.pki.model.CVCInfoBean;
import de.governikus.eumw.poseidas.server.pki.model.CVCRequestModel;
import lombok.extern.slf4j.Slf4j;


/**
 * This controller shows the details page for a single entity.
 *
 * @author bpr
 */
@Slf4j
@Controller
@RequestMapping(ContextPaths.ADMIN_CONTEXT_PATH + ContextPaths.DETAILS)
public class CVCController
{

  /**
   * This string represents the OK {@link ManagementMessage}
   */
  private static final String CO_MSG_OK_OK = "CO.msg.ok.ok";

  private static final String SUCCESS = "success";

  private static final String RESULT_MESSAGE = "resultMessage";

  private static final String ERROR = "error";

  private static final String REDIRECT_PREFIX = "redirect:";

  private final Map<String, CVCInfoBean> cvcList;

  private final RequestSignerCertificateService requestSignerCertificateService;

  /**
   * On startup, create a hashmap containing the entityID and the corresponding {@link CVCInfoBean} object
   *
   * @param data the reference to the {@link PermissionDataHandling}
   * @param requestSignerCertificateService
   */
  public CVCController(PermissionDataHandlingMBean data,
                       RequestSignerCertificateService requestSignerCertificateService,
                       CvcTlsCheck cvcTlsCheck,
                       TerminalPermissionAO facade)
  {
    this.requestSignerCertificateService = requestSignerCertificateService;
    cvcList = new HashMap<>();
    CoreConfigurationDto config = PoseidasConfigurator.getInstance().getCurrentConfig();
    for ( ServiceProviderDto entry : config.getServiceProvider().values() )
    {
      if (entry.getEpaConnectorConfiguration() == null)
      {
        continue;
      }
      cvcList.put(entry.getEntityID(),
                  new CVCInfoBean(entry, data, cvcTlsCheck, facade, requestSignerCertificateService));
    }
  }

  /**
   * This route represents the details view for the given entityID
   */
  @GetMapping("{entityID}")
  public String details(@PathVariable String entityID, Model model, HttpServletResponse response) throws IOException
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
  @PostMapping("{entityID}/check")
  public String check(@PathVariable String entityID, RedirectAttributes redirectAttributes)
  {
    String result = cvcList.get(entityID).checkReadyForFirstRequest();
    if (CO_MSG_OK_OK.equals(result))
    {
      redirectAttributes.addFlashAttribute(SUCCESS, true);
      redirectAttributes.addFlashAttribute(RESULT_MESSAGE, "Connection check succeeded");
    }
    else
    {
      redirectAttributes.addFlashAttribute(ERROR, true);
      redirectAttributes.addFlashAttribute(RESULT_MESSAGE, "Connection check failed");
    }
    return REDIRECT_PREFIX + ContextPaths.ADMIN_CONTEXT_PATH + ContextPaths.DETAILS + "/" + entityID;
  }

  /**
   * This route peforms the initial certificate request
   */
  @PostMapping("{entityID}/initialRequest")
  public String initialRequest(@PathVariable String entityID,
                               @ModelAttribute CVCRequestModel form,
                               RedirectAttributes redirectAttributes)
  {
    cvcList.get(entityID).setCountryCode(form.getCountryCode());
    cvcList.get(entityID).setChrMnemonic(form.getCHRMnemonic());
    cvcList.get(entityID).setSequenceNumber(form.getSequenceNumber());

    String result = cvcList.get(entityID).initRequest();
    if (CO_MSG_OK_OK.equals(result))
    {
      redirectAttributes.addFlashAttribute(SUCCESS, true);
      redirectAttributes.addFlashAttribute(RESULT_MESSAGE, "Initial request succeeded");
    }
    else
    {
      redirectAttributes.addFlashAttribute(ERROR, true);
      redirectAttributes.addFlashAttribute(RESULT_MESSAGE, "Initial request failed");
    }

    return REDIRECT_PREFIX + ContextPaths.ADMIN_CONTEXT_PATH + ContextPaths.DETAILS + "/" + entityID;
  }

  /**
   * This route performs the renewal of the black list
   */
  @PostMapping("{entityID}/renewBlackList")
  public String renewBlackList(@PathVariable String entityID, RedirectAttributes redirectAttributes)
  {
    String result = cvcList.get(entityID).renewBlackList();
    if (CO_MSG_OK_OK.equals(result))
    {
      redirectAttributes.addFlashAttribute(SUCCESS, true);
      redirectAttributes.addFlashAttribute(RESULT_MESSAGE, "Renew black list succeeded");
    }
    else
    {
      redirectAttributes.addFlashAttribute(ERROR, true);
      redirectAttributes.addFlashAttribute(RESULT_MESSAGE, "Renew black list failed");
    }
    return REDIRECT_PREFIX + ContextPaths.ADMIN_CONTEXT_PATH + ContextPaths.DETAILS + "/" + entityID;
  }

  /**
   * This route performs the renewal of the master defect list
   */
  @PostMapping("{entityID}/renewMasterDefectList")
  public String renewMasterDefectList(@PathVariable String entityID, RedirectAttributes redirectAttributes)
  {
    String result = cvcList.get(entityID).renewMasterAndDefectList();
    if (CO_MSG_OK_OK.equals(result))
    {
      redirectAttributes.addFlashAttribute(SUCCESS, true);
      redirectAttributes.addFlashAttribute(RESULT_MESSAGE, "Renew master and defect list succeeded");
    }
    else
    {
      redirectAttributes.addFlashAttribute(ERROR, true);
      redirectAttributes.addFlashAttribute(RESULT_MESSAGE, "Renew master and defect list failed");
    }
    return REDIRECT_PREFIX + ContextPaths.ADMIN_CONTEXT_PATH + ContextPaths.DETAILS + "/" + entityID;
  }

  /**
   * This route performs the renewal CVC
   */
  @PostMapping("{entityID}/renewCVC")
  public String renewCVC(@PathVariable String entityID, RedirectAttributes redirectAttributes)
  {
    String result = cvcList.get(entityID).triggerCertRenewal();
    if (CO_MSG_OK_OK.equals(result))
    {
      redirectAttributes.addFlashAttribute(SUCCESS, true);
      redirectAttributes.addFlashAttribute(RESULT_MESSAGE, "Renew CVC succeeded");
    }
    else
    {
      redirectAttributes.addFlashAttribute(ERROR, true);
      redirectAttributes.addFlashAttribute(RESULT_MESSAGE, "Renew CVC failed");
    }
    return REDIRECT_PREFIX + ContextPaths.ADMIN_CONTEXT_PATH + ContextPaths.DETAILS + "/" + entityID;
  }

  /**
   * This route performs the generation of a @{@link de.governikus.eumw.poseidas.server.pki.RequestSignerCertificate}
   **/
  @PostMapping("{entityID}/generateRSC")
  public String generateRSC(@PathVariable String entityID,
                            RedirectAttributes redirectAttributes,
                            @ModelAttribute CVCRequestModel form)
  {
    boolean isSuccess = requestSignerCertificateService.generateNewPendingRequestSignerCertificate(entityID,
                                                                                                   form.getRscChr(),
                                                                                                   RequestSignerCertificateServiceImpl.MAXIMUM_LIFESPAN_IN_MONTHS);
    if (isSuccess)
    {
      redirectAttributes.addFlashAttribute(SUCCESS, true);
      redirectAttributes.addFlashAttribute(RESULT_MESSAGE, "Request signer certificate successfully created");
    }
    else
    {
      redirectAttributes.addFlashAttribute(ERROR, true);
      redirectAttributes.addFlashAttribute(RESULT_MESSAGE, "Creation of request signer certificate failed");
    }
    return REDIRECT_PREFIX + ContextPaths.ADMIN_CONTEXT_PATH + ContextPaths.DETAILS + "/" + entityID;
  }

  /**
   * This route performs the download of a request signer certificate.
   *
   * @return ResponseEntity with the request signer certificate as byte array
   */
  @GetMapping(value = "{entityID}/downloadRSC", produces = MediaType.APPLICATION_OCTET_STREAM_VALUE)
  public ResponseEntity<byte[]> downloadRequestSignerCertificate(@PathVariable String entityID)
    throws RequestSignerDownloadException
  {
    X509Certificate requestSignerCertificate = requestSignerCertificateService.getRequestSignerCertificate(entityID);
    if (requestSignerCertificate != null)
    {
      String filename = requestSignerCertificate.getSubjectDN().toString();
      try
      {
        return ResponseEntity.ok()
                             .header("Content-Disposition", "attachment; filename=\"" + filename + ".cer\"")
                             .contentType(MediaType.APPLICATION_OCTET_STREAM)
                             .body(requestSignerCertificate.getEncoded());
      }
      catch (CertificateEncodingException e)
      {
        log.error("Can not encode request signer certificate", e);
        throw new RequestSignerDownloadException(entityID);
      }
    }
    log.error("No request signer certificate found");
    throw new RequestSignerDownloadException(entityID);
  }

  /**
   * This {@link ExceptionHandler} handles the {@link RequestSignerDownloadException}. In case of exception the client
   * is returned to a html site where an error message will be displayed.
   *
   * @param model Model with the information to be displayed
   * @param response {@link HttpServletResponse} the response to the client
   * @param exception the {@link RequestSignerDownloadException} with information about the error
   * @return String as html site
   */
  @ExceptionHandler(RequestSignerDownloadException.class)
  public String handleRequestSignerDownloadException(Model model,
                                                     HttpServletResponse response,
                                                     RequestSignerDownloadException exception)
    throws IOException
  {
    String entityId = exception.getEntityId();
    model.addAttribute(ERROR, true);
    model.addAttribute(RESULT_MESSAGE, "Download of request signer certificate failed. Please check your log.");
    return details(entityId, model, response);
  }
}

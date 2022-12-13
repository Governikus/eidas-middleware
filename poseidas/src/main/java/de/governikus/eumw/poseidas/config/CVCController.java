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
import java.net.URI;
import java.net.URISyntaxException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.List;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import de.governikus.eumw.config.EidasMiddlewareConfig;
import de.governikus.eumw.eidascommon.ContextPaths;
import de.governikus.eumw.poseidas.config.model.ServiceProviderDetails;
import de.governikus.eumw.poseidas.config.model.forms.CVCRequestModel;
import de.governikus.eumw.poseidas.gov2server.constants.admin.ManagementMessage;
import de.governikus.eumw.poseidas.server.exception.RequestSignerDownloadException;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationService;
import de.governikus.eumw.poseidas.server.pki.PermissionDataHandlingMBean;
import de.governikus.eumw.poseidas.server.pki.RequestSignerCertificateService;
import de.governikus.eumw.poseidas.server.pki.RequestSignerCertificateServiceImpl;
import de.governikus.eumw.poseidas.server.pki.ServiceProviderStatusService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;


/**
 * This controller shows the details page for a single entity.
 *
 * @author bpr
 */
@Slf4j
@Controller
@RequiredArgsConstructor
@RequestMapping(ContextPaths.ADMIN_CONTEXT_PATH + ContextPaths.DETAILS)
public class CVCController
{

  /**
   * This string represents the OK {@link ManagementMessage}
   */
  static final String CO_MSG_OK_OK = "CO.msg.ok.ok";

  private static final String SUCCESS = "msg";

  private static final String RESULT_MESSAGE = "resultMessage";

  private static final String ERROR = "error";

  private static final String REDIRECT_PREFIX = "redirect:";

  private static final String ERROR_MESSAGE_NO_SP_PRESENT = "No service provider present with name: ";

  private static final String JUMP_TO_TAB = "jumpToTab";

  private static final String CVC = "CVC";

  private static final String LISTS = "Lists";

  private static final String RSC = "RSC";

  private final PermissionDataHandlingMBean data;

  private final RequestSignerCertificateService requestSignerCertificateService;

  private final ConfigurationService configService;

  private final ServiceProviderStatusService serviceProviderStatusService;


  /**
   * This route represents the details view for the given entityID
   */
  @GetMapping("{entityID}")
  public String details(@PathVariable String entityID,
                        Model model,
                        RedirectAttributes redirectAttributes,
                        @RequestHeader(value = "referer", required = false) String referer)
    throws IOException
  {
    ServiceProviderDetails serviceProviderDetails = getServiceProviderDetails(entityID);
    if (entityID == null || serviceProviderDetails == null)
    {
      // Redirect to the referer is needed, when open the detail site from different places than dashboard site.
      String responseTo;
      try
      {
        if (referer == null)
        {
          log.warn("No referer found in header to redirect to");
          return redirectToDashBoardWithErrorMessage(redirectAttributes, ERROR_MESSAGE_NO_SP_PRESENT, entityID);
        }
        else
        {
          responseTo = new URI(referer).getPath();
        }
      }
      catch (URISyntaxException e)
      {
        log.warn("Could not resolve referer URL to open eID service provider detail site.", e);
        return redirectToDashBoardWithErrorMessage(redirectAttributes, ERROR_MESSAGE_NO_SP_PRESENT, entityID);
      }

      redirectAttributes.addFlashAttribute(ERROR, ERROR_MESSAGE_NO_SP_PRESENT + entityID);
      return "redirect:" + responseTo;
    }
    model.addAttribute("entity", serviceProviderDetails);
    model.addAttribute("entityID", entityID);
    model.addAttribute("form", new CVCRequestModel());
    return "pages/details";
  }

  /**
   * This route performs the connection check to the DVCA
   */
  @PostMapping("{entityID}/check")
  public String check(@PathVariable String entityID, RedirectAttributes redirectAttributes)
  {
    ServiceProviderDetails serviceProviderDetails = getServiceProviderDetails(entityID);
    if (serviceProviderDetails == null)
    {
      return redirectToDashBoardWithErrorMessage(redirectAttributes,
                                                 "Check connection failed: " + ERROR_MESSAGE_NO_SP_PRESENT,
                                                 entityID);
    }
    String result = data.checkReadyForFirstRequest(entityID).toString();
    if (CO_MSG_OK_OK.equals(result))
    {
      redirectAttributes.addFlashAttribute(SUCCESS, "Connection check succeeded");
    }
    else
    {
      redirectAttributes.addFlashAttribute(ERROR, "Connection check failed: " + result);
    }
    return REDIRECT_PREFIX + ContextPaths.ADMIN_CONTEXT_PATH + ContextPaths.DETAILS + '/' + entityID;
  }

  /**
   * This route performs the initial certificate request
   */
  @PostMapping("{entityID}/initialRequest")
  public String initialRequest(@PathVariable String entityID,
                               @ModelAttribute CVCRequestModel form,
                               RedirectAttributes redirectAttributes)
  {
    ServiceProviderDetails serviceProviderDetails = getServiceProviderDetails(entityID);
    if (serviceProviderDetails == null)
    {
      return redirectToDashBoardWithErrorMessage(redirectAttributes,
                                                 "Initial request failed: " + ERROR_MESSAGE_NO_SP_PRESENT,
                                                 entityID);
    }

    String result = data.requestFirstTerminalCertificate(entityID,
                                                         form.getCountryCode(),
                                                         form.getChrMnemonic(),
                                                         form.getSequenceNumber())
                        .toString();
    if (CO_MSG_OK_OK.equals(result))
    {
      redirectAttributes.addFlashAttribute(SUCCESS, "Initial request succeeded");
    }
    else
    {

      redirectAttributes.addFlashAttribute(ERROR, "Initial request failed: " + result);
    }
    redirectAttributes.addFlashAttribute(JUMP_TO_TAB, CVC);
    return REDIRECT_PREFIX + ContextPaths.ADMIN_CONTEXT_PATH + ContextPaths.DETAILS + '/' + entityID;
  }

  /**
   * This route performs the renewal of the black list
   */
  @PostMapping("{entityID}/renewBlackList")
  public String renewBlackList(@PathVariable String entityID, RedirectAttributes redirectAttributes)
  {
    ServiceProviderDetails serviceProviderDetails = getServiceProviderDetails(entityID);
    if (serviceProviderDetails == null)
    {
      return redirectToDashBoardWithErrorMessage(redirectAttributes,
                                                 "Renew black list failed: " + ERROR_MESSAGE_NO_SP_PRESENT,
                                                 entityID);
    }
    String result = data.renewBlackList(entityID).toString();
    if (CO_MSG_OK_OK.equals(result))
    {
      redirectAttributes.addFlashAttribute(SUCCESS, "Renew black list succeeded");
    }
    else
    {
      redirectAttributes.addFlashAttribute(ERROR, "Renew black list failed: " + result);
    }
    redirectAttributes.addFlashAttribute(JUMP_TO_TAB, LISTS);
    return REDIRECT_PREFIX + ContextPaths.ADMIN_CONTEXT_PATH + ContextPaths.DETAILS + '/' + entityID;
  }

  /**
   * This route performs the renewal of the master defect list
   */
  @PostMapping("{entityID}/renewMasterDefectList")
  public String renewMasterDefectList(@PathVariable String entityID, RedirectAttributes redirectAttributes)
  {
    ServiceProviderDetails serviceProviderDetails = getServiceProviderDetails(entityID);
    if (serviceProviderDetails == null)
    {
      return redirectToDashBoardWithErrorMessage(redirectAttributes,
                                                 "Renew Master and Defect List failed: " + ERROR_MESSAGE_NO_SP_PRESENT,
                                                 entityID);
    }
    String result = data.renewMasterAndDefectList(entityID).toString();
    if (CO_MSG_OK_OK.equals(result))
    {
      redirectAttributes.addFlashAttribute(SUCCESS, "Renew Master and Defect List succeeded");
    }
    else
    {
      redirectAttributes.addFlashAttribute(ERROR, "Renew Master and Defect List failed: " + result);
    }
    redirectAttributes.addFlashAttribute(JUMP_TO_TAB, LISTS);
    return REDIRECT_PREFIX + ContextPaths.ADMIN_CONTEXT_PATH + ContextPaths.DETAILS + '/' + entityID;
  }

  /**
   * This route performs the renewal CVC
   */
  @PostMapping("{entityID}/renewCVC")
  public String renewCVC(@PathVariable String entityID, RedirectAttributes redirectAttributes)
  {
    ServiceProviderDetails serviceProviderDetails = getServiceProviderDetails(entityID);
    if (serviceProviderDetails == null)
    {
      return redirectToDashBoardWithErrorMessage(redirectAttributes,
                                                 "Renew CVC failed: " + ERROR_MESSAGE_NO_SP_PRESENT,
                                                 entityID);
    }
    String result = data.triggerCertRenewal(entityID).toString();
    if (CO_MSG_OK_OK.equals(result))
    {
      redirectAttributes.addFlashAttribute(SUCCESS, "Renew CVC succeeded");
    }
    else
    {
      redirectAttributes.addFlashAttribute(ERROR, "Renew CVC failed: " + result);
    }
    redirectAttributes.addFlashAttribute(JUMP_TO_TAB, CVC);
    return REDIRECT_PREFIX + ContextPaths.ADMIN_CONTEXT_PATH + ContextPaths.DETAILS + '/' + entityID;
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
      redirectAttributes.addFlashAttribute(SUCCESS, "Request signer certificate successfully created");
    }
    else
    {
      redirectAttributes.addFlashAttribute(ERROR, "Creation of request signer certificate failed");
    }
    redirectAttributes.addFlashAttribute(JUMP_TO_TAB, RSC);
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

  private ServiceProviderDetails getServiceProviderDetails(String serviceProviderId)
  {
    return configService.getConfiguration()
                        .map(EidasMiddlewareConfig::getEidConfiguration)
                        .map(EidasMiddlewareConfig.EidConfiguration::getServiceProvider)
                        .stream()
                        .flatMap(List::stream)
                        .filter(serviceProviderType -> serviceProviderId.equals(serviceProviderType.getName()))
                        .findFirst()
                        .map(serviceProviderType -> new ServiceProviderDetails(serviceProviderType,
                                                                               data.getPermissionDataInfo(serviceProviderType.getCVCRefID(),
                                                                                                          false),
                                                                               serviceProviderStatusService.getServiceProviderStatus(serviceProviderType)))
                        .orElse(null);
  }

  private String redirectToDashBoardWithErrorMessage(RedirectAttributes redirectAttributes,
                                                     String errorMessage,
                                                     String entityID)
  {
    log.warn(ERROR_MESSAGE_NO_SP_PRESENT + " {}", entityID);
    redirectAttributes.addFlashAttribute(CVCController.ERROR, errorMessage + ERROR_MESSAGE_NO_SP_PRESENT + entityID);
    return CVCController.REDIRECT_PREFIX + ContextPaths.ADMIN_CONTEXT_PATH + ContextPaths.DASHBOARD;
  }

  /**
   * This {@link ExceptionHandler} handles the {@link RequestSignerDownloadException}. In case of exception the client
   * is returned to a html site where an error message will be displayed.
   *
   * @param model Model with the information to be displayed
   * @param redirectAttributes the redirectAttributes to the client
   * @param exception the {@link RequestSignerDownloadException} with information about the error
   * @return String as html site
   */
  @ExceptionHandler(RequestSignerDownloadException.class)
  public String handleRequestSignerDownloadException(Model model,
                                                     RedirectAttributes redirectAttributes,
                                                     RequestSignerDownloadException exception)
    throws IOException
  {
    String entityId = exception.getEntityId();
    model.addAttribute(ERROR, "Download of request signer certificate failed. Please check your log.");
    return details(entityId, model, redirectAttributes, "");
  }
}

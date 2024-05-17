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
import java.util.Objects;
import java.util.Optional;

import jakarta.validation.Valid;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
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
import de.governikus.eumw.poseidas.server.pki.TerminalPermissionAOBean;
import de.governikus.eumw.poseidas.server.pki.TlsClientRenewalService;
import de.governikus.eumw.poseidas.server.pki.entities.RequestSignerCertificate;
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

  private static final String TLS = "TLS";

  public static final String ENTITYID = "entityid";

  private final PermissionDataHandlingMBean data;

  private final RequestSignerCertificateService requestSignerCertificateService;

  private final ConfigurationService configService;

  private final ServiceProviderStatusService serviceProviderStatusService;

  private final TerminalPermissionAOBean terminalPermissionAOBean;

  private final TlsClientRenewalService tlsClientRenewalService;


  /**
   * This route represents the details view for the given entityID
   */
  @GetMapping()
  public String details(@RequestParam(ENTITYID) String entityID,
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
          return redirectToStatusPageWithErrorMessage(redirectAttributes, ERROR_MESSAGE_NO_SP_PRESENT, entityID);
        }
        else
        {
          responseTo = new URI(referer).getPath();
        }
      }
      catch (URISyntaxException e)
      {
        log.warn("Could not resolve referer URL to open eID service provider detail site.", e);
        return redirectToStatusPageWithErrorMessage(redirectAttributes, ERROR_MESSAGE_NO_SP_PRESENT, entityID);
      }

      redirectAttributes.addFlashAttribute(ERROR, ERROR_MESSAGE_NO_SP_PRESENT + entityID);
      return "redirect:" + responseTo;
    }
    String currentTlsClientKeyPairName = serviceProviderDetails.getCurrentTlsClientKeyPairName();
    model.addAttribute("entity", serviceProviderDetails);
    model.addAttribute("entityID", entityID);
    model.addAttribute("currentTlsClientKeyPairName", currentTlsClientKeyPairName);
    model.addAttribute("form", Objects.requireNonNullElseGet(model.getAttribute("form"), CVCRequestModel::new));
    return "pages/details";
  }

  /**
   * This route performs the connection check to the DVCA
   */
  @PostMapping("/check")
  public String check(@RequestParam(ENTITYID) String entityID, RedirectAttributes redirectAttributes)
  {
    ServiceProviderDetails serviceProviderDetails = getServiceProviderDetails(entityID);
    if (serviceProviderDetails == null)
    {
      return redirectToStatusPageWithErrorMessage(redirectAttributes,
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
    redirectAttributes.addAttribute(ENTITYID, entityID);
    return REDIRECT_PREFIX + ContextPaths.ADMIN_CONTEXT_PATH + ContextPaths.DETAILS;
  }

  /**
   * This route performs the initial certificate request
   */
  @PostMapping("/initialRequest")
  public String initialRequest(@RequestParam(ENTITYID) String entityID,
                               @Valid @ModelAttribute CVCRequestModel form,
                               BindingResult bindingResult,
                               RedirectAttributes redirectAttributes)
  {
    ServiceProviderDetails serviceProviderDetails = getServiceProviderDetails(entityID);
    if (serviceProviderDetails == null)
    {
      return redirectToStatusPageWithErrorMessage(redirectAttributes,
                                                  "Initial request failed: " + ERROR_MESSAGE_NO_SP_PRESENT,
                                                  entityID);
    }
    if (bindingResult.hasErrors())
    {

      redirectAttributes.addFlashAttribute("org.springframework.validation.BindingResult.form", bindingResult);
      redirectAttributes.addFlashAttribute("form", form);
      redirectAttributes.addFlashAttribute(ERROR,
                                           "Initial request was not sent. Please check \"Initial CVC request\" below.");

    }
    else
    {

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
    }
    redirectAttributes.addFlashAttribute(JUMP_TO_TAB, CVC);
    redirectAttributes.addAttribute(ENTITYID, entityID);
    return REDIRECT_PREFIX + ContextPaths.ADMIN_CONTEXT_PATH + ContextPaths.DETAILS;
  }

  /**
   * This route performs the renewal of the black list
   */
  @PostMapping("/renewBlackList")
  public String renewBlackList(@RequestParam(ENTITYID) String entityID, RedirectAttributes redirectAttributes)
  {
    ServiceProviderDetails serviceProviderDetails = getServiceProviderDetails(entityID);
    if (serviceProviderDetails == null)
    {
      return redirectToStatusPageWithErrorMessage(redirectAttributes,
                                                  "Renew block list failed: " + ERROR_MESSAGE_NO_SP_PRESENT,
                                                  entityID);
    }
    String result = data.renewBlackList(entityID).toString();
    if (CO_MSG_OK_OK.equals(result))
    {
      redirectAttributes.addFlashAttribute(SUCCESS, "Renew block list succeeded");
    }
    else
    {
      redirectAttributes.addFlashAttribute(ERROR, "Renew block list failed: " + result);
    }
    redirectAttributes.addFlashAttribute(JUMP_TO_TAB, LISTS);
    redirectAttributes.addAttribute(ENTITYID, entityID);
    return REDIRECT_PREFIX + ContextPaths.ADMIN_CONTEXT_PATH + ContextPaths.DETAILS;
  }

  /**
   * This route performs the renewal of the master defect list
   */
  @PostMapping("/renewMasterDefectList")
  public String renewMasterDefectList(@RequestParam(ENTITYID) String entityID, RedirectAttributes redirectAttributes)
  {
    ServiceProviderDetails serviceProviderDetails = getServiceProviderDetails(entityID);
    if (serviceProviderDetails == null)
    {
      return redirectToStatusPageWithErrorMessage(redirectAttributes,
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
    redirectAttributes.addAttribute(ENTITYID, entityID);
    return REDIRECT_PREFIX + ContextPaths.ADMIN_CONTEXT_PATH + ContextPaths.DETAILS;
  }

  /**
   * This route performs the renewal CVC
   */
  @PostMapping("/renewCVC")
  public String renewCVC(@RequestParam(ENTITYID) String entityID, RedirectAttributes redirectAttributes)
  {
    ServiceProviderDetails serviceProviderDetails = getServiceProviderDetails(entityID);
    if (serviceProviderDetails == null)
    {
      return redirectToStatusPageWithErrorMessage(redirectAttributes,
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
    redirectAttributes.addAttribute(ENTITYID, entityID);
    return REDIRECT_PREFIX + ContextPaths.ADMIN_CONTEXT_PATH + ContextPaths.DETAILS;
  }

  /**
   * This route performs the generation of a @{@link RequestSignerCertificate}
   **/
  @PostMapping("/generateRSC")
  public String generateRSC(@RequestParam(ENTITYID) String entityID,
                            RedirectAttributes redirectAttributes,
                            @ModelAttribute CVCRequestModel form)
  {
    Optional<String> result = requestSignerCertificateService.generateNewPendingRequestSignerCertificate(entityID,
                                                                                                         form.getRscChr(),
                                                                                                         RequestSignerCertificateServiceImpl.MAXIMUM_LIFESPAN_IN_MONTHS);
    if (result.isEmpty())
    {
      redirectAttributes.addFlashAttribute(SUCCESS, "Request signer certificate successfully created");
    }
    else
    {
      redirectAttributes.addFlashAttribute(ERROR, "Creation of request signer certificate failed: " + result.get());
    }
    redirectAttributes.addFlashAttribute(JUMP_TO_TAB, RSC);
    redirectAttributes.addAttribute(ENTITYID, entityID);
    return REDIRECT_PREFIX + ContextPaths.ADMIN_CONTEXT_PATH + ContextPaths.DETAILS;
  }

  /**
   * This route performs the download of a request signer certificate.
   *
   * @return ResponseEntity with the request signer certificate as byte array
   */
  @GetMapping(value = "/downloadRSC", produces = MediaType.APPLICATION_OCTET_STREAM_VALUE)
  public ResponseEntity<byte[]> downloadRequestSignerCertificate(@RequestParam(ENTITYID) String entityID)
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
   * Generates a new RSC and sends the new RSC to the DVCA
   */
  @GetMapping("/generateAndSendRSC")
  public String generateAndSendRSC(@RequestParam(ENTITYID) String entityID,
                                   RedirectAttributes redirectAttributes,
                                   @ModelAttribute CVCRequestModel form)
  {
    Optional<String> result = requestSignerCertificateService.renewRSC(entityID);
    if (result.isEmpty())
    {
      redirectAttributes.addFlashAttribute(SUCCESS, "Request signer certificate successfully renewed");
    }
    else
    {
      redirectAttributes.addFlashAttribute(ERROR, "Sending of new request signer certificate failed: " + result.get());
    }
    redirectAttributes.addFlashAttribute(JUMP_TO_TAB, RSC);
    redirectAttributes.addAttribute(ENTITYID, entityID);
    return REDIRECT_PREFIX + ContextPaths.ADMIN_CONTEXT_PATH + ContextPaths.DETAILS;
  }

  /**
   * Sends the pending RSC to the DVCA
   */
  @GetMapping("/sendPendingRSC")
  public String sendPendingRSC(@RequestParam(ENTITYID) String entityID, RedirectAttributes redirectAttributes)
  {
    Optional<String> result = requestSignerCertificateService.sendPendingRSC(entityID);
    if (result.isEmpty())
    {
      redirectAttributes.addFlashAttribute(SUCCESS, "Pending Request signer certificate successfully sent");
    }
    else
    {
      redirectAttributes.addFlashAttribute(ERROR,
                                           "Sending of pending request signer certificate failed: " + result.get());
    }
    redirectAttributes.addFlashAttribute(JUMP_TO_TAB, RSC);
    redirectAttributes.addAttribute(ENTITYID, entityID);
    return REDIRECT_PREFIX + ContextPaths.ADMIN_CONTEXT_PATH + ContextPaths.DETAILS;
  }

  /**
   * Deletes the pending RSC
   */
  @GetMapping("/deletePendingRSC")
  public String deletePendingRSC(@RequestParam(ENTITYID) String entityID,
                                 RedirectAttributes redirectAttributes,
                                 @ModelAttribute CVCRequestModel form)
  {
    Optional<String> result = requestSignerCertificateService.deletePendingRSC(entityID);
    if (result.isEmpty())
    {
      redirectAttributes.addFlashAttribute(SUCCESS, "Pending request signer certificate successfully deleted");
    }
    else
    {
      redirectAttributes.addFlashAttribute(ERROR,
                                           "Deleting of pending request signer certificate failed: " + result.get());
    }
    redirectAttributes.addFlashAttribute(JUMP_TO_TAB, RSC);
    redirectAttributes.addAttribute(ENTITYID, entityID);
    return REDIRECT_PREFIX + ContextPaths.ADMIN_CONTEXT_PATH + ContextPaths.DETAILS;
  }

  @PostMapping("/renewTLSClientCert")
  public String renewTlsClientKey(@RequestParam(ENTITYID) String entityID,
                                  @ModelAttribute CVCRequestModel form,
                                  RedirectAttributes redirectAttributes)
  {
    String tlsKeyPairNameToUseForNewCsr = form.getTlsKeyPairNameToUseForNewCsr();
    Optional<String> optionalErrorMessage;
    if ("generateNewKeyPair".equals(tlsKeyPairNameToUseForNewCsr) || form.isGenerateNewKey())
    {
      optionalErrorMessage = tlsClientRenewalService.generateAndSendCsrWithNewKey(entityID);
    }
    else
    {
      optionalErrorMessage = tlsClientRenewalService.generateAndSendCsr(entityID, tlsKeyPairNameToUseForNewCsr);
    }
    if (optionalErrorMessage.isEmpty())
    {
      redirectAttributes.addFlashAttribute(SUCCESS, "Renewal of TLS client certificate was successfully sent");
    }
    else
    {
      redirectAttributes.addFlashAttribute(ERROR, "Sending of CSR failed: " + optionalErrorMessage.get());
    }
    redirectAttributes.addFlashAttribute(JUMP_TO_TAB, TLS);
    redirectAttributes.addAttribute(ENTITYID, entityID);
    return REDIRECT_PREFIX + ContextPaths.ADMIN_CONTEXT_PATH + ContextPaths.DETAILS;
  }

  @GetMapping("/pollTLSClientCert")
  public String renewTlsClientKey(@RequestParam(ENTITYID) String entityID, RedirectAttributes redirectAttributes)
  {
    Optional<String> optionalErrorMessage = tlsClientRenewalService.fetchCertificate(entityID);
    if (optionalErrorMessage.isEmpty())
    {
      redirectAttributes.addFlashAttribute(SUCCESS, "Poll of TLS client certificate was successful.");
    }
    else
    {
      redirectAttributes.addFlashAttribute(ERROR,
                                           "Poll of new TLS client certificate failed: " + optionalErrorMessage.get());
    }
    redirectAttributes.addFlashAttribute(JUMP_TO_TAB, TLS);
    redirectAttributes.addAttribute(ENTITYID, entityID);
    return REDIRECT_PREFIX + ContextPaths.ADMIN_CONTEXT_PATH + ContextPaths.DETAILS;
  }

  @GetMapping("/deletePendingCsr")
  public String deletePendingCsr(@RequestParam(ENTITYID) String entityID, RedirectAttributes redirectAttributes)
  {
    log.info("Deleting the pending CSR for entityID: {}", entityID);
    tlsClientRenewalService.deletePendingCsr(entityID);
    redirectAttributes.addFlashAttribute(JUMP_TO_TAB, TLS);
    redirectAttributes.addAttribute(ENTITYID, entityID);
    return REDIRECT_PREFIX + ContextPaths.ADMIN_CONTEXT_PATH + ContextPaths.DETAILS;
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
                                                                               serviceProviderStatusService.getServiceProviderStatus(serviceProviderType),
                                                                               terminalPermissionAOBean))
                        .orElse(null);
  }

  private String redirectToStatusPageWithErrorMessage(RedirectAttributes redirectAttributes,
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

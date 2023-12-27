package de.governikus.eumw.poseidas.config;

import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Optional;

import jakarta.validation.Valid;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import de.governikus.eumw.config.ConnectorMetadataType;
import de.governikus.eumw.config.ContactType;
import de.governikus.eumw.config.EidasMiddlewareConfig;
import de.governikus.eumw.config.OrganizationType;
import de.governikus.eumw.eidascommon.ContextPaths;
import de.governikus.eumw.eidascommon.ErrorCodeException;
import de.governikus.eumw.eidascommon.Utils;
import de.governikus.eumw.eidasstarterkit.EidasSigner;
import de.governikus.eumw.poseidas.config.model.forms.EidasConfigModel;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationException;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationService;
import de.governikus.eumw.poseidas.server.pki.HSMServiceHolder;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;


@Controller
@RequestMapping(ContextPaths.ADMIN_CONTEXT_PATH + ContextPaths.EIDAS_CONFIG)
@RequiredArgsConstructor
@Slf4j
public class EidasController
{

  public static final String INDEX_TEMPLATE = "pages/eidasConfiguration";

  public static final String REDIRECT_TO_INDEX = "redirect:" + ContextPaths.ADMIN_CONTEXT_PATH
                                                 + ContextPaths.EIDAS_CONFIG;

  private final ConfigurationService configurationService;

  private final HSMServiceHolder hsmServiceHolder;

  @Value("#{'${hsm.type:}' == 'PKCS11'}")
  private boolean isHsmInUse;

  @GetMapping("")
  public String index(Model model, @ModelAttribute String error, @ModelAttribute String msg)
  {
    if (error != null && !error.isBlank())
    {
      model.addAttribute("error", error);
    }
    if (msg != null && !msg.isBlank())
    {
      model.addAttribute("msg", msg);
    }

    EidasConfigModel configModel = toConfigModel(configurationService.getConfiguration()
                                                                     .map(EidasMiddlewareConfig::getServerUrl)
                                                                     .orElse(""),
                                                 configurationService.getConfiguration()
                                                                     .map(EidasMiddlewareConfig::getEidasConfiguration)
                                                                     .orElse(new EidasMiddlewareConfig.EidasConfiguration()));
    model.addAttribute("eidasConfigModel", configModel);

    KeyStore hsmKeyStore = hsmServiceHolder.getKeyStore();
    if (hsmKeyStore != null)
    {
      X509Certificate certificate = null;
      try
      {
        certificate = (X509Certificate)hsmKeyStore.getCertificate(EidasSigner.SAML_SIGNING);
      }
      catch (Exception e)
      {
        log.warn("Cannot get the signature certificate of the middleware from the HSM", e);
        String errorMessage = error + "Cannot get the signature certificate of the middleware from the HSM: "
                              + e.getMessage();
        model.addAttribute("error", errorMessage);
      }
      if (certificate != null)
      {
        try
        {
          Utils.ensureKeySize(certificate);
        }
        catch (ErrorCodeException e)
        {
          // Already logged in Utils, only the message of the UI is necessary
          String errorMessage = "The signature certificate in the HSM does not meet the crypto requirements: "
                                + e.getMessage();
          model.addAttribute("error", errorMessage);
        }
      }
    }
    else if (StringUtils.isNotBlank(configModel.getSignatureKeyPairName()))
    {
      Optional<String> optionalErrorMessage = checkSignatureCert(configModel.getSignatureKeyPairName());
      if (optionalErrorMessage.isPresent())
      {
        String errorMessage = error + optionalErrorMessage.get();
        model.addAttribute("error", errorMessage);
      }
    }

    return INDEX_TEMPLATE;
  }

  @PostMapping("")
  public String save(@Valid @ModelAttribute EidasConfigModel configModel,
                     BindingResult bindingResult,
                     RedirectAttributes redirectAttributes)
  {


    // Return with error if hsm is not used
    // or hsm is used and there are more errors than at the field "signatureKeyPairName"
    // because the input field for the signature key pair is not displayed when hsm us used
    if (bindingResult.hasErrors() && !(isHsmInUse && bindingResult.getErrorCount() == bindingResult.getFieldErrorCount()
                                       && !bindingResult.getFieldErrors()
                                                        .parallelStream()
                                                        .anyMatch(e -> !"signatureKeyPairName".equals(e.getField()))))
    {
      return INDEX_TEMPLATE;
    }

    if (StringUtils.isNotBlank(configModel.getSignatureKeyPairName()))
    {
      Optional<String> optionalErrorMessage = checkSignatureCert(configModel.getSignatureKeyPairName());
      if (optionalErrorMessage.isPresent())
      {
        bindingResult.addError(new FieldError("eidasConfigModel", "signatureKeyPairName", optionalErrorMessage.get()));
        return INDEX_TEMPLATE;
      }
    }

    final EidasMiddlewareConfig eidasMiddlewareConfig = configurationService.getConfiguration()
                                                                            .orElse(new EidasMiddlewareConfig());
    eidasMiddlewareConfig.setEidasConfiguration(toConfigType(configModel));
    eidasMiddlewareConfig.setServerUrl(configModel.getServerUrl());
    configurationService.saveConfiguration(eidasMiddlewareConfig, false);


    redirectAttributes.addFlashAttribute("msg", "eIDAS configuration saved!");
    return REDIRECT_TO_INDEX;
  }

  private Optional<String> checkSignatureCert(String signatureKeyPairName)
  {
    try
    {
      configurationService.getSamlKeyPair(signatureKeyPairName);
    }
    catch (ConfigurationException e)
    {
      log.warn("The signature certificate  does not meet the crypto requirements", e);
      return Optional.of("The signature certificate does not meet the crypto requirements: " + e.getMessage());
    }
    return Optional.empty();
  }


  private EidasConfigModel toConfigModel(String serverUrl, EidasMiddlewareConfig.EidasConfiguration config)
  {
    if (config.getContactPerson() == null)
    {
      config.setContactPerson(new ContactType());
    }

    if (config.getOrganization() == null)
    {
      config.setOrganization(new OrganizationType());
    }

    return new EidasConfigModel(config.getPublicServiceProviderName(), serverUrl, config.getCountryCode(),
                                config.getContactPerson().getCompany(), config.getContactPerson().getGivenname(),
                                config.getContactPerson().getSurname(), config.getContactPerson().getEmail(),
                                config.getContactPerson().getTelephone(), config.getOrganization().getDisplayname(),
                                config.getOrganization().getName(), config.getOrganization().getLanguage(),
                                config.getOrganization().getUrl(), config.getSignatureKeyPairName(), config.isDoSign());
  }

  private EidasMiddlewareConfig.EidasConfiguration toConfigType(EidasConfigModel model)
  {
    final List<ConnectorMetadataType> metadata = configurationService.getConfiguration()
                                                                     .map(EidasMiddlewareConfig::getEidasConfiguration)
                                                                     .map(EidasMiddlewareConfig.EidasConfiguration::getConnectorMetadata)
                                                                     .orElse(List.of());

    return new EidasMiddlewareConfig.EidasConfiguration(metadata, model.isSignMetadata(), 0, model.getCountryCode(),
                                                        new ContactType(model.getContactPersonCompanyName(),
                                                                        model.getContactPersonName(),
                                                                        model.getContactPersonSurname(),
                                                                        model.getContactPersonMail(),
                                                                        model.getContactPersonTel()),
                                                        new OrganizationType(model.getOrganizationDisplayname(),
                                                                             model.getOrganizationName(),
                                                                             model.getOrganizationLanguage(),
                                                                             model.getOrganizationUrl()),
                                                        model.getPublicServiceProviderName(), null,
                                                        StringUtils.isBlank(model.getSignatureKeyPairName()) ? null
                                                          : model.getSignatureKeyPairName(),
                                                        configurationService.getConfiguration()
                                                                            .map(EidasMiddlewareConfig::getEidasConfiguration)
                                                                            .map(EidasMiddlewareConfig.EidasConfiguration::getMetadataSignatureVerificationCertificateName)
                                                                            .orElse(null));
  }
}

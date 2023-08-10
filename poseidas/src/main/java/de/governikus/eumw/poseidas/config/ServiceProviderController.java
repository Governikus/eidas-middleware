package de.governikus.eumw.poseidas.config;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.sql.Date;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.stream.Collectors;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import de.governikus.eumw.config.DvcaConfigurationType;
import de.governikus.eumw.config.EidasMiddlewareConfig;
import de.governikus.eumw.config.KeyPairType;
import de.governikus.eumw.config.KeyStoreType;
import de.governikus.eumw.config.ServiceProviderType;
import de.governikus.eumw.eidascommon.ContextPaths;
import de.governikus.eumw.poseidas.cardbase.Hex;
import de.governikus.eumw.poseidas.config.model.KeypairInfoHolder;
import de.governikus.eumw.poseidas.config.model.ServiceProviderViewModel;
import de.governikus.eumw.poseidas.config.model.forms.ServiceProviderConfigModel;
import de.governikus.eumw.poseidas.eidserver.crl.CertificationRevocationListImpl;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationService;
import de.governikus.eumw.poseidas.server.pki.TerminalPermissionAO;
import de.governikus.eumw.utils.key.KeyStoreSupporter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;


@Controller
@RequiredArgsConstructor
@Slf4j
@RequestMapping(ContextPaths.ADMIN_CONTEXT_PATH + ContextPaths.SERVICE_PROVIDER_PATH)
public class ServiceProviderController
{

  private static final String ERROR_ATTRIBUTE = "error";

  private static final String MSG_ATTRIBUTE = "msg";

  private final SimpleDateFormat dateFormat = new SimpleDateFormat("dd.MM.yyyy", Locale.ENGLISH);

  public static final String SERVICE_PROVIDER_CONFIG_MODEL_ATTRIBUTE_NAME = "serviceProviderConfigModel";

  private static final String SERVICE_PROVIDER_TEMPLATE_FOLDER = "pages/serviceProvider";

  private static final String SERVICE_PROVIDER_DELETE_TEMPLATE = SERVICE_PROVIDER_TEMPLATE_FOLDER
                                                                 + "/deleteServiceProvider";

  private static final String INDEX_TEMPLATE = SERVICE_PROVIDER_TEMPLATE_FOLDER + "/index";

  private static final String SERVICE_PROVIDER_CONFIGURATION_FORM_TEMPLATE = SERVICE_PROVIDER_TEMPLATE_FOLDER
                                                                             + "/serviceProviderConfigurationForm";

  private static final String REDIRECT_TO_SERVICE_PROVIDER_INDEX = "redirect:" + ContextPaths.ADMIN_CONTEXT_PATH
                                                                   + ContextPaths.SERVICE_PROVIDER_PATH;

  private final ConfigurationService configurationService;

  private final TerminalPermissionAO facade;

  @Value("#{'${hsm.type:}' == 'PKCS11'}")
  private boolean isHsmInUse;

  @GetMapping
  public String index(Model model, @ModelAttribute String error, @ModelAttribute String msg)
  {
    insertMessagesIntoModel(model, error, msg);

    final List<ServiceProviderType> serviceProviderConfigurations = getServiceProviderConfigurations();
    List<ServiceProviderViewModel> serviceProviderViewModels = new ArrayList<>(serviceProviderConfigurations.size());
    for ( ServiceProviderType serviceProviderConfiguration : serviceProviderConfigurations )
    {
      try
      {
        serviceProviderViewModels.add(toServiceProviderViewModel(serviceProviderConfiguration));
      }
      catch (CertificateException | KeyStoreException e)
      {
        if (log.isWarnEnabled())
        {
          log.warn("Could not display service provider " + serviceProviderConfiguration.getName(), e);
        }
        model.addAttribute(ERROR_ATTRIBUTE, e.getMessage());
      }
    }

    model.addAttribute("serviceProviderViewModel", serviceProviderViewModels);
    return INDEX_TEMPLATE;
  }

  private void insertMessagesIntoModel(Model model, @ModelAttribute String error, @ModelAttribute String msg)
  {
    if (error != null && !error.isBlank())
    {
      model.addAttribute(ERROR_ATTRIBUTE, error);
    }
    if (msg != null && !msg.isBlank())
    {
      model.addAttribute(MSG_ATTRIBUTE, msg);
    }
  }

  private ServiceProviderViewModel toServiceProviderViewModel(ServiceProviderType serviceProviderType)
    throws CertificateException, KeyStoreException
  {
    final Optional<KeyPairType> caKeyPair = isHsmInUse ? Optional.empty()
      : configurationService.getConfiguration()
                            .map(EidasMiddlewareConfig::getKeyData)
                            .map(EidasMiddlewareConfig.KeyData::getKeyPair)
                            .stream()
                            .flatMap(List::stream)
                            .filter(f -> f.getName().equals(serviceProviderType.getClientKeyPairName()))
                            .findAny();

    return new ServiceProviderViewModel(serviceProviderType.getDvcaConfigurationName(),
                                        keyPairTypeToInfoHolder(caKeyPair.orElse(null)), serviceProviderType.getName(),
                                        serviceProviderType.isEnabled());
  }

  @GetMapping("/create")
  public String create(Model model, @ModelAttribute String error, @ModelAttribute String msg)
  {
    insertMessagesIntoModel(model, error, msg);


    model.addAttribute(SERVICE_PROVIDER_CONFIG_MODEL_ATTRIBUTE_NAME, new ServiceProviderConfigModel());
    model.addAttribute("dvcaValues", getDvcaConfigNames());

    return SERVICE_PROVIDER_CONFIGURATION_FORM_TEMPLATE;
  }

  @GetMapping("/edit")
  public String edit(Model model,
                     @ModelAttribute String error,
                     @ModelAttribute String msg,
                     @RequestParam("serviceprovidername") String name,
                     RedirectAttributes redirectAttributes)
  {
    insertMessagesIntoModel(model, error, msg);

    final Optional<ServiceProviderType> serviceProviderTypeOptional = getServiceProviderConfigurations().stream()
                                                                                                        .filter(c -> name.equals(c.getName()))
                                                                                                        .findAny();
    if (serviceProviderTypeOptional.isEmpty())
    {
      redirectAttributes.addFlashAttribute(ERROR_ATTRIBUTE, "No service provider configuration found: " + name);
      return REDIRECT_TO_SERVICE_PROVIDER_INDEX;
    }

    model.addAttribute(SERVICE_PROVIDER_CONFIG_MODEL_ATTRIBUTE_NAME, toConfigModel(serviceProviderTypeOptional.get()));
    model.addAttribute("dvcaValues", getDvcaConfigNames());

    return SERVICE_PROVIDER_CONFIGURATION_FORM_TEMPLATE;
  }

  @PostMapping("/create")
  public String saveAfterCreate(Model model,
                                @Valid @ModelAttribute ServiceProviderConfigModel serviceProviderConfigModel,
                                BindingResult bindingResult,
                                RedirectAttributes redirectAttributes)
  {
    // check if new name is already in use
    if (getServiceProviderConfigurations().parallelStream()
                                          .anyMatch(s -> serviceProviderConfigModel.getName()
                                                                                   .equalsIgnoreCase(s.getName())))
    {
      bindingResult.addError(new FieldError(SERVICE_PROVIDER_CONFIG_MODEL_ATTRIBUTE_NAME, "name",
                                            serviceProviderConfigModel.getName(), true, null, null,
                                            "This name is already in use"));
    }

    // check if new name is already in use as cvc ref id
    if (getServiceProviderConfigurations().parallelStream()
                                          .anyMatch(s -> serviceProviderConfigModel.getName()
                                                                                   .equalsIgnoreCase(s.getCVCRefID())))
    {
      bindingResult.addError(new FieldError(SERVICE_PROVIDER_CONFIG_MODEL_ATTRIBUTE_NAME, "name",
                                            serviceProviderConfigModel.getName(), true, null, null,
                                            "The name is already used as CVCRefId by another service provider."));
    }

    if (checkIfBindingresultHasRelevantErrors(model, bindingResult))
    {
      return SERVICE_PROVIDER_CONFIGURATION_FORM_TEMPLATE;
    }

    final EidasMiddlewareConfig eidasMiddlewareConfig = configurationService.getConfiguration()
                                                                            .orElse(new EidasMiddlewareConfig());
    final EidasMiddlewareConfig.EidConfiguration eidConfiguration = Optional.ofNullable(eidasMiddlewareConfig.getEidConfiguration())
                                                                            .orElse(new EidasMiddlewareConfig.EidConfiguration());


    // save
    eidConfiguration.getServiceProvider().add(serviceProviderConfigModel.toServiceProviderType());
    configurationService.saveConfiguration(eidasMiddlewareConfig, false);

    redirectAttributes.addFlashAttribute(MSG_ATTRIBUTE,
                                         "Saved service provider successfully: "
                                                        + serviceProviderConfigModel.getName());
    CertificationRevocationListImpl.tryInitialize(configurationService, facade);
    return REDIRECT_TO_SERVICE_PROVIDER_INDEX;
  }

  @PostMapping("/edit")
  public String saveAfterChange(Model model,
                                @RequestParam("serviceprovidername") String currentName,
                                @Valid @ModelAttribute ServiceProviderConfigModel serviceProviderConfigModel,
                                BindingResult bindingResult,
                                RedirectAttributes redirectAttributes)
  {

    boolean nameChanged = !serviceProviderConfigModel.getName().equals(currentName);

    // check if name is blank
    if (serviceProviderConfigModel.getName().isBlank())
    {
      bindingResult.addError(new FieldError(SERVICE_PROVIDER_CONFIG_MODEL_ATTRIBUTE_NAME, "name",
                                            serviceProviderConfigModel.getName(), true, null, null,
                                            "May not be empty"));
    }

    // check if name is taken on new
    final Optional<ServiceProviderType> optionalCurrentServiceProviderEntry = getServiceProviderConfigurations().stream()
                                                                                                                .filter(s -> serviceProviderConfigModel.getName()
                                                                                                                                                       .equalsIgnoreCase(s.getName()))
                                                                                                                .findFirst();

    if (nameChanged && !serviceProviderConfigModel.getName().isBlank()
        && optionalCurrentServiceProviderEntry.isPresent())
    {
      bindingResult.addError(new FieldError(SERVICE_PROVIDER_CONFIG_MODEL_ATTRIBUTE_NAME, "name",
                                            serviceProviderConfigModel.getName(), true, null, null,
                                            "This name is already in use"));
    }

    if (checkIfBindingresultHasRelevantErrors(model, bindingResult))
    {
      return SERVICE_PROVIDER_CONFIGURATION_FORM_TEMPLATE;
    }

    final EidasMiddlewareConfig eidasMiddlewareConfig = configurationService.getConfiguration()
                                                                            .orElse(new EidasMiddlewareConfig());
    final EidasMiddlewareConfig.EidConfiguration eidConfiguration = Optional.ofNullable(eidasMiddlewareConfig.getEidConfiguration())
                                                                            .orElse(new EidasMiddlewareConfig.EidConfiguration());

    // remove current entry
    List<ServiceProviderType> currentEntriesWithName = eidConfiguration.getServiceProvider()
                                                                       .stream()
                                                                       .filter(s -> s.getName()
                                                                                     .equalsIgnoreCase(currentName))
                                                                       .collect(Collectors.toList());
    eidConfiguration.getServiceProvider().removeAll(currentEntriesWithName);

    // set PublicServiceProviderName if necessary
    if (nameChanged && eidasMiddlewareConfig.getEidasConfiguration() != null
        && eidasMiddlewareConfig.getEidasConfiguration().getPublicServiceProviderName().equals(currentName))
    {
      eidasMiddlewareConfig.getEidasConfiguration().setPublicServiceProviderName(serviceProviderConfigModel.getName());
    }

    // save and keep cvc ref id of current instance or use the current name
    eidConfiguration.getServiceProvider()
                    .add(serviceProviderConfigModel.toServiceProviderType(currentEntriesWithName.stream()
                                                                                                .findFirst()
                                                                                                .map(ServiceProviderType::getCVCRefID)
                                                                                                .orElse(currentName)));
    configurationService.saveConfiguration(eidasMiddlewareConfig, false);

    redirectAttributes.addFlashAttribute(MSG_ATTRIBUTE,
                                         "Saved service provider successfully: "
                                                        + serviceProviderConfigModel.getName());
    CertificationRevocationListImpl.tryInitialize(configurationService, facade);
    return REDIRECT_TO_SERVICE_PROVIDER_INDEX;
  }

  /**
   * Return true if hsm is not used or hsm is used and there are more errors than at the field "clientKeyPairName"
   * because the input field for the client key pair is not displayed when hsm is used.
   *
   * @param model model to add dvca config names
   * @param bindingResult
   * @return true if relevant errors where found, otherwise false
   */
  private boolean checkIfBindingresultHasRelevantErrors(Model model, BindingResult bindingResult)
  {
    if (bindingResult.hasErrors() && !(isHsmInUse && bindingResult.getErrorCount() == bindingResult.getFieldErrorCount()
                                       && !bindingResult.getFieldErrors()
                                                        .parallelStream()
                                                        .anyMatch(e -> !"clientKeyPairName".equals(e.getField()))))
    {
      model.addAttribute("dvcaValues", getDvcaConfigNames());
      return true;
    }
    return false;
  }

  @GetMapping("/remove")
  public String deleteServiceProvider(Model model,
                                      @RequestParam("serviceprovidername") String name,
                                      RedirectAttributes redirectAttributes)
  {
    if (addErrorIfServiceProviderNotFound(name, redirectAttributes))
    {
      return REDIRECT_TO_SERVICE_PROVIDER_INDEX;
    }

    // is public service provider
    if (isServiceProviderThePublicServiceProvider(name, redirectAttributes))
    {
      return REDIRECT_TO_SERVICE_PROVIDER_INDEX;
    }

    model.addAttribute("name", name);

    return SERVICE_PROVIDER_DELETE_TEMPLATE;
  }

  private boolean addErrorIfServiceProviderNotFound(String name, RedirectAttributes redirectAttributes)
  {
    // check existing
    if (getServiceProviderConfigurations().stream().noneMatch(d -> name.equals(d.getName())))
    {
      redirectAttributes.addFlashAttribute(ERROR_ATTRIBUTE, "Service provider not found: " + name);
      return true;
    }
    return false;
  }

  @PostMapping("/remove")
  public String deleteServiceProviderConfirmed(@RequestParam("serviceprovidername") String name,
                                               RedirectAttributes redirectAttributes)
  {
    // check existing
    if (addErrorIfServiceProviderNotFound(name, redirectAttributes))
    {
      return REDIRECT_TO_SERVICE_PROVIDER_INDEX;
    }

    // is public service provider
    if (isServiceProviderThePublicServiceProvider(name, redirectAttributes))
    {
      return REDIRECT_TO_SERVICE_PROVIDER_INDEX;
    }

    // remove from config

    final EidasMiddlewareConfig eidasMiddlewareConfig = configurationService.getConfiguration()
                                                                            .orElse(new EidasMiddlewareConfig());
    final EidasMiddlewareConfig.EidConfiguration eidConfiguration = Optional.ofNullable(eidasMiddlewareConfig.getEidConfiguration())
                                                                            .orElse(new EidasMiddlewareConfig.EidConfiguration());
    final Optional<ServiceProviderType> serviceProviderTypeOptional = eidConfiguration.getServiceProvider()
                                                                                      .stream()
                                                                                      .filter(d -> name.equals(d.getName()))
                                                                                      .findAny();

    if (serviceProviderTypeOptional.isEmpty())
    {
      redirectAttributes.addFlashAttribute(MSG_ATTRIBUTE, "Service provider not found: " + name);
      return REDIRECT_TO_SERVICE_PROVIDER_INDEX;
    }
    eidConfiguration.getServiceProvider().remove(serviceProviderTypeOptional.get());
    configurationService.saveConfiguration(eidasMiddlewareConfig, false);

    redirectAttributes.addFlashAttribute(MSG_ATTRIBUTE, "Service provider deleted: " + name);
    return REDIRECT_TO_SERVICE_PROVIDER_INDEX;

  }

  private boolean isServiceProviderThePublicServiceProvider(String name, RedirectAttributes redirectAttributes)
  {
    if (configurationService.getConfiguration()
                            .map(EidasMiddlewareConfig::getEidasConfiguration)
                            .map(EidasMiddlewareConfig.EidasConfiguration::getPublicServiceProviderName)
                            .orElse("")
                            .equals(name))
    {
      redirectAttributes.addFlashAttribute(ERROR_ATTRIBUTE,
                                           "This service provider is currently configured as the eIDAS public service provider and can not be deleted: "
                                                            + name);
      return true;
    }
    return false;
  }

  private List<String> getDvcaConfigNames()
  {
    return configurationService.getConfiguration()
                               .map(EidasMiddlewareConfig::getEidConfiguration)
                               .map(EidasMiddlewareConfig.EidConfiguration::getDvcaConfiguration)
                               .stream()
                               .flatMap(List::stream)
                               .map(DvcaConfigurationType::getName)
                               .collect(Collectors.toList());
  }

  private List<ServiceProviderType> getServiceProviderConfigurations()
  {
    return configurationService.getConfiguration()
                               .map(EidasMiddlewareConfig::getEidConfiguration)
                               .map(EidasMiddlewareConfig.EidConfiguration::getServiceProvider)
                               .orElse(List.of());
  }

  private ServiceProviderConfigModel toConfigModel(ServiceProviderType configurationType)
  {
    return new ServiceProviderConfigModel(configurationType.getDvcaConfigurationName(),
                                          configurationType.getClientKeyPairName(), configurationType.getName(),
                                          configurationType.isEnabled());
  }


  private KeypairInfoHolder keyPairTypeToInfoHolder(KeyPairType keyPairType)
    throws CertificateException, KeyStoreException
  {
    if (keyPairType == null)
    {
      return null;
    }

    final Optional<KeyStoreType> keyStoreTypeOptional = configurationService.getConfiguration()
                                                                            .stream()
                                                                            .map(EidasMiddlewareConfig::getKeyData)
                                                                            .map(EidasMiddlewareConfig.KeyData::getKeyStore)
                                                                            .flatMap(List::stream)
                                                                            .filter(k -> keyPairType.getKeyStoreName()
                                                                                                    .equals(k.getName()))
                                                                            .findFirst();
    if (keyStoreTypeOptional.isEmpty())
    {
      throw new KeyStoreException("Could not find keystore '" + keyPairType.getKeyStoreName() + "' in configuration");
    }
    final KeyStoreType keyStoreType = keyStoreTypeOptional.get();

    KeyStore keyStore = KeyStoreSupporter.readKeyStore(keyStoreType.getKeyStore(),
                                                       KeyStoreSupporter.KeyStoreType.valueOf(keyStoreType.getType()
                                                                                                          .value()),
                                                       keyStoreType.getPassword());


    try
    {
      X509Certificate cert = (X509Certificate)keyStore.getCertificate(keyPairType.getAlias());

      return new KeypairInfoHolder(keyPairType.getName(), cert.getSubjectX500Principal().getName(),
                                   cert.getIssuerX500Principal().getName(), "0x" + Hex.hexify(cert.getSerialNumber()),
                                   dateFormat.format(cert.getNotAfter()),
                                   cert.getNotAfter().after(Date.from(Instant.now())), keyStoreType.getName(),
                                   keyPairType.getAlias());
    }
    catch (KeyStoreException e)
    {
      log.debug("Exception while working with certificate!", e);
      throw new CertificateException("Could not work with certificate of keypair: " + keyPairType.getName(), e);
    }
  }

}

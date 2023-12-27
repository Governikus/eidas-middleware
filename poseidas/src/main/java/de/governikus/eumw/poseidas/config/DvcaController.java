package de.governikus.eumw.poseidas.config;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.sql.Date;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

import jakarta.validation.Valid;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import de.governikus.eumw.config.CertificateType;
import de.governikus.eumw.config.DvcaConfigurationType;
import de.governikus.eumw.config.EidasMiddlewareConfig;
import de.governikus.eumw.config.ServiceProviderType;
import de.governikus.eumw.eidascommon.ContextPaths;
import de.governikus.eumw.poseidas.cardbase.Hex;
import de.governikus.eumw.poseidas.config.model.CertificateInfoHolder;
import de.governikus.eumw.poseidas.config.model.forms.DvcaConfigModel;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationService;
import de.governikus.eumw.utils.key.SecurityProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;


/**
 * Handles all requests that are necessary for the management of dvca configurations
 */
@Controller
@RequestMapping(ContextPaths.ADMIN_CONTEXT_PATH + "/dvcaConfiguration")
@RequiredArgsConstructor
@Slf4j
public class DvcaController
{

  public static final String DVCA_TEMPLATE_FOLDER = "pages/dvcaConfiguration";

  public static final String INDEX_TEMPLATE = DVCA_TEMPLATE_FOLDER + "/index";

  public static final String DVCA_CONFIGURATION_FORM_TEMPLATE = DVCA_TEMPLATE_FOLDER + "/dvcaConfigurationForm";

  public static final String REDIRECT_TO_INDEX = "redirect:" + ContextPaths.ADMIN_CONTEXT_PATH + "/dvcaConfiguration";

  private final ConfigurationService configurationService;

  private final SimpleDateFormat dateFormat = new SimpleDateFormat("dd.MM.yyyy", Locale.ENGLISH);

  /**
   * Show all dvca configurations
   */
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

    Map<String, CertificateInfoHolder> certificateInfos = new ConcurrentHashMap<>();
    configurationService.getCertificateTypes()
                        .stream()
                        .map(this::certificateTypeToInfoHolder)
                        .filter(Optional::isPresent)
                        .map(Optional::get)
                        .forEach(e -> certificateInfos.put(e.getName(), e));

    model.addAttribute("certificateInfoHolderMap", certificateInfos);
    model.addAttribute("dvcaConfigurations", getDvcaConfigurations());

    return INDEX_TEMPLATE;
  }

  private List<DvcaConfigurationType> getDvcaConfigurations()
  {
    return configurationService.getConfiguration()
                               .map(EidasMiddlewareConfig::getEidConfiguration)
                               .map(EidasMiddlewareConfig.EidConfiguration::getDvcaConfiguration)
                               .orElse(List.of());
  }

  private Optional<CertificateInfoHolder> certificateTypeToInfoHolder(CertificateType certificateType)
  {

    try
    {
      CertificateFactory certFactory = CertificateFactory.getInstance("X.509", SecurityProvider.BOUNCY_CASTLE_PROVIDER);
      X509Certificate cert = (X509Certificate)certFactory.generateCertificate(new ByteArrayInputStream(certificateType.getCertificate()));
      return Optional.of(new CertificateInfoHolder(certificateType.getName(), cert.getSubjectX500Principal().getName(),
                                                   cert.getIssuerX500Principal().getName(),
                                                   "0x" + Hex.hexify(cert.getSerialNumber()),
                                                   dateFormat.format(cert.getNotAfter()),
                                                   cert.getNotAfter().after(Date.from(Instant.now())),
                                                   certificateType.getKeystore(), certificateType.getAlias()));
    }
    catch (CertificateException e)
    {
      if (log.isWarnEnabled())
      {
        log.warn("Exception while working with certificate! " + certificateType.getName(), e);
      }
      return Optional.empty();
    }
  }

  /**
   * Create a new dvca config
   */
  @GetMapping("/create")
  public String create(Model model, @ModelAttribute String error, @ModelAttribute String msg)
  {
    if (error != null && !error.isBlank())
    {
      model.addAttribute("error", error);
    }
    if (msg != null && !msg.isBlank())
    {
      model.addAttribute("msg", msg);
    }

    model.addAttribute("dvcaConfigModel", new DvcaConfigModel());

    return DVCA_CONFIGURATION_FORM_TEMPLATE;
  }

  /**
   * Edit an existing dvca config
   */
  @GetMapping("/edit")
  public String edit(Model model,
                     @ModelAttribute String error,
                     @ModelAttribute String msg,
                     @RequestParam("dvcaname") String name,
                     RedirectAttributes redirectAttributes)
  {
    if (error != null && !error.isBlank())
    {
      model.addAttribute("error", error);
    }
    if (msg != null && !msg.isBlank())
    {
      model.addAttribute("msg", msg);
    }

    final Optional<DvcaConfigurationType> dvcaConfigurationTypeOptional = getDvcaConfigurations().stream()
                                                                                                 .filter(c -> name.equals(c.getName()))
                                                                                                 .findAny();
    if (dvcaConfigurationTypeOptional.isEmpty())
    {
      redirectAttributes.addFlashAttribute("error", "No dvca configuration found with with name " + name);
      return REDIRECT_TO_INDEX;
    }
    model.addAttribute("dvcaConfigModel", toModel(dvcaConfigurationTypeOptional.get()));

    return DVCA_CONFIGURATION_FORM_TEMPLATE;
  }

  /**
   * Remove an existing dvca config
   */
  @GetMapping("/remove")
  public String remove(Model model,
                       @RequestParam("dvcaname") String name,
                       @RequestParam(name = "yes", required = false) Optional<String> confirmed,
                       RedirectAttributes redirectAttributes)
  {

    final Optional<DvcaConfigurationType> dvcaConfigurationTypeOptional = getDvcaConfigurations().stream()
                                                                                                 .filter(c -> name.equals(c.getName()))
                                                                                                 .findAny();
    if (dvcaConfigurationTypeOptional.isEmpty())
    {
      redirectAttributes.addFlashAttribute("error", "No dvca configuration found with with name " + name);
      return REDIRECT_TO_INDEX;
    }

    // Check if referenced

    String referencingServiceprovider = configurationService.getConfiguration()
                                                            .map(EidasMiddlewareConfig::getEidConfiguration)
                                                            .map(EidasMiddlewareConfig.EidConfiguration::getServiceProvider)
                                                            .stream()
                                                            .flatMap(List::stream)
                                                            .filter(s -> name.equalsIgnoreCase(s.getDvcaConfigurationName()))
                                                            .map(ServiceProviderType::getName)
                                                            .collect(Collectors.joining(","));
    if (!referencingServiceprovider.isEmpty())
    {
      redirectAttributes.addFlashAttribute("error",
                                           "Dvca configuration " + name + " is still used by some service provider: "
                                                    + referencingServiceprovider);
      return REDIRECT_TO_INDEX;
    }

    if (confirmed.isPresent())
    {
      final EidasMiddlewareConfig eidasMiddlewareConfig = configurationService.getConfiguration().get(); // There must
                                                                                                         // exists a
                                                                                                         // configuration
                                                                                                         // at this
                                                                                                         // point
      eidasMiddlewareConfig.getEidConfiguration().getDvcaConfiguration().remove(dvcaConfigurationTypeOptional.get());
      configurationService.saveConfiguration(eidasMiddlewareConfig, false);
      redirectAttributes.addFlashAttribute("msg", "Dvca configuration removed: " + name);
      return REDIRECT_TO_INDEX;
    }

    model.addAttribute("name", name);

    return DVCA_TEMPLATE_FOLDER + "/removeDvcaConfig";
  }


  /**
   * Save edited or new dvca config
   */
  @PostMapping({"/edit", "/create"})
  public String edit(Model model,
                     @RequestParam(name = "dvcaname", required = false) Optional<String> currentName,
                     @Valid @ModelAttribute DvcaConfigModel dvcaConfigModel,
                     BindingResult bindingResult,
                     RedirectAttributes redirectAttributes)
  {

    // Check if name is already taken
    if (dvcaConfigModel.isNewconfig()
        && configurationService.getConfiguration()
                               .map(EidasMiddlewareConfig::getEidConfiguration)
                               .map(EidasMiddlewareConfig.EidConfiguration::getDvcaConfiguration)
                               .stream()
                               .flatMap(List::stream)
                               .anyMatch(d -> dvcaConfigModel.getName().equalsIgnoreCase(d.getName())))
    {
      bindingResult.addError(new FieldError("dvcaConfigModel", "name", "This name is already taken!"));
    }


    if (bindingResult.hasErrors())
    {
      return DVCA_CONFIGURATION_FORM_TEMPLATE;
    }

    final EidasMiddlewareConfig config = configurationService.getConfiguration().orElse(new EidasMiddlewareConfig());

    if (config.getEidConfiguration() == null)
    {
      config.setEidConfiguration(new EidasMiddlewareConfig.EidConfiguration());
    }

    final EidasMiddlewareConfig.EidConfiguration eidConfiguration = config.getEidConfiguration();

    final Optional<DvcaConfigurationType> optionalOldDvcaConfig = eidConfiguration.getDvcaConfiguration()
                                                                                  .parallelStream()
                                                                                  .filter(p -> currentName.orElse("")
                                                                                                   .equalsIgnoreCase(p.getName()))
                                                                                  .findAny();

    // If an existing DVCA configuration is edited and its name is changed, change also the name in the service
    // providers that use this DVCA configuration
    if (currentName.isPresent() && !currentName.get().equals(dvcaConfigModel.getName()))
    {
      eidConfiguration.getServiceProvider()
                      .parallelStream()
                      .filter(s -> currentName.orElse("").equalsIgnoreCase(s.getDvcaConfigurationName()))
                      .forEach(s -> s.setDvcaConfigurationName(dvcaConfigModel.getName()));
    }

    if (optionalOldDvcaConfig.isPresent())
    {
      eidConfiguration.getDvcaConfiguration().remove(optionalOldDvcaConfig.get());
    }

    eidConfiguration.getDvcaConfiguration().add(toConfigurationtype(dvcaConfigModel));

    configurationService.saveConfiguration(config, false);

    redirectAttributes.addFlashAttribute("msg", "DVCA configuration saved: " + dvcaConfigModel.getName());
    return REDIRECT_TO_INDEX;
  }

  private DvcaConfigModel toModel(DvcaConfigurationType configurationType)
  {
    return new DvcaConfigModel(configurationType.getServerSSLCertificateName(),
                               configurationType.getBlackListTrustAnchorCertificateName(),
                               configurationType.getMasterListTrustAnchorCertificateName(), configurationType.getName(),
                               configurationType.getTerminalAuthServiceUrl(),
                               configurationType.getRestrictedIdServiceUrl(),
                               configurationType.getPassiveAuthServiceUrl(),
                               configurationType.getDvcaCertificateDescriptionServiceUrl(), false);
  }

  private DvcaConfigurationType toConfigurationtype(DvcaConfigModel dvcaConfigModel)
  {
    return new DvcaConfigurationType(dvcaConfigModel.getName(), dvcaConfigModel.getTerminalAuthServiceUrl(),
                                     dvcaConfigModel.getRestrictedIdServiceUrl(),
                                     dvcaConfigModel.getPassiveAuthServiceUrl(),
                                     dvcaConfigModel.getDvcaCertificateDescrptionServiceUrl(),
                                     dvcaConfigModel.getServerSSLCertificateName(),
                                     dvcaConfigModel.getBlackListTrustAnchorCertificateName(),
                                     dvcaConfigModel.getMasterListTrustAnchorCertificateName());
  }
}

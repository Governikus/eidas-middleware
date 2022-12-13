package de.governikus.eumw.poseidas.config;

import java.util.Arrays;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import javax.validation.Valid;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import de.governikus.eumw.config.EidasMiddlewareConfig;
import de.governikus.eumw.eidascommon.ContextPaths;
import de.governikus.eumw.poseidas.config.model.forms.EidConfigModel;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationService;
import lombok.RequiredArgsConstructor;


@Controller
@RequiredArgsConstructor
@RequestMapping(ContextPaths.ADMIN_CONTEXT_PATH + ContextPaths.EID_CONFIG)
public class EidController
{

  public static final String FORM_TEMPLATE = "pages" + ContextPaths.EID_CONFIG;

  private final ConfigurationService configurationService;

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

    model.addAttribute("eidConfigModel",
                       new EidConfigModel(configurationService.getConfiguration()
                                                              .map(EidasMiddlewareConfig::getEidConfiguration)
                                                              .map(EidasMiddlewareConfig.EidConfiguration::getAllowedEidMeans)
                                                              .orElse("A,ID,UB")));
    return FORM_TEMPLATE;
  }

  @PostMapping("")
  public String save(Model model,
                     @Valid @ModelAttribute EidConfigModel eidConfigModel,
                     BindingResult bindingResult,
                     RedirectAttributes redirectAttributes)
  {

    if (bindingResult.hasErrors())
    {
      return FORM_TEMPLATE;
    }

    final EidasMiddlewareConfig config = configurationService.getConfiguration().orElse(new EidasMiddlewareConfig());
    EidasMiddlewareConfig.EidConfiguration eidConfiguration = Optional.ofNullable(config.getEidConfiguration())
                                                                      .orElse(new EidasMiddlewareConfig.EidConfiguration());

    String allowedEidMeans = eidConfigModel.getAllowedEidMeans();
    Set<String> allowedEidMeansSet = Arrays.stream(allowedEidMeans.split(","))
                                           .map(String::trim)
                                           .filter(s -> !s.isBlank())
                                           .collect(Collectors.toSet());
    // Always store A,ID,UB in config
    allowedEidMeansSet.addAll(Set.of("A", "ID", "UB"));

    eidConfiguration.setAllowedEidMeans(allowedEidMeansSet.stream().sorted().collect(Collectors.joining(",")));
    config.setEidConfiguration(eidConfiguration);
    configurationService.saveConfiguration(config, false);

    redirectAttributes.addFlashAttribute("msg", "eID configuration saved.");
    return "redirect:" + ContextPaths.ADMIN_CONTEXT_PATH + ContextPaths.EID_CONFIG;
  }
}

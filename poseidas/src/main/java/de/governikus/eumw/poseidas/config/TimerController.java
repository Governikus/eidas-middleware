package de.governikus.eumw.poseidas.config;

import java.util.Optional;

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
import de.governikus.eumw.config.TimerConfigurationType;
import de.governikus.eumw.config.TimerType;
import de.governikus.eumw.config.TimerTypeCertRenewal;
import de.governikus.eumw.config.TimerUnit;
import de.governikus.eumw.eidascommon.ContextPaths;
import de.governikus.eumw.poseidas.config.model.forms.TimerConfigModel;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;


@Controller
@RequiredArgsConstructor
@RequestMapping(ContextPaths.ADMIN_CONTEXT_PATH + ContextPaths.TIMER_CONFIG)
@Slf4j
public class TimerController
{

  public static final String CONFIG_TEMPLATE = "pages" + ContextPaths.TIMER_CONFIG;

  public static final String REDIRECT_TO_INDEX = "redirect:" + ContextPaths.ADMIN_CONTEXT_PATH
                                                 + ContextPaths.TIMER_CONFIG;

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

    TimerConfigurationType timerConfigurationType = configurationService.getConfiguration()
                                                                        .map(EidasMiddlewareConfig::getEidConfiguration)
                                                                        .map(EidasMiddlewareConfig.EidConfiguration::getTimerConfiguration)
                                                                        .orElse(new TimerConfigurationType());
    setDefaultTimerValues(timerConfigurationType);
    model.addAttribute("timerConfigModel", toConfigModel(timerConfigurationType));
    return CONFIG_TEMPLATE;
  }

  @PostMapping("")
  public String save(Model model,
                     @Valid @ModelAttribute TimerConfigModel timerConfigModel,
                     BindingResult bindingResult,
                     RedirectAttributes redirectAttributes)
  {

    if (bindingResult.hasErrors())
    {
      return CONFIG_TEMPLATE;
    }

    final EidasMiddlewareConfig eidasMiddlewareConfig = configurationService.getConfiguration()
                                                                            .orElseGet(EidasMiddlewareConfig::new);
    final EidasMiddlewareConfig.EidConfiguration eidConfiguration = Optional.ofNullable(eidasMiddlewareConfig.getEidConfiguration())
                                                                            .orElse(new EidasMiddlewareConfig.EidConfiguration());
    eidConfiguration.setTimerConfiguration(toConfigType(timerConfigModel));
    eidasMiddlewareConfig.setEidConfiguration(eidConfiguration);

    configurationService.saveConfiguration(eidasMiddlewareConfig, false);

    redirectAttributes.addFlashAttribute("msg", "Timer configuration saved.");
    return REDIRECT_TO_INDEX;
  }

  private TimerConfigModel toConfigModel(TimerConfigurationType timerConfigurationType)
  {
    var timerConfigModelBuilder = TimerConfigModel.builder();
    if (timerConfigurationType.getCertRenewal() != null)
    {
      timerConfigModelBuilder.cvcRenewalLength(timerConfigurationType.getCertRenewal().getLength());
      timerConfigModelBuilder.cvcRenewalUnit(timerConfigurationType.getCertRenewal().getUnit());
      timerConfigModelBuilder.hoursRefreshCvcBeforeExpiration(timerConfigurationType.getCertRenewal()
                                                                                    .getHoursRefreshCVCBeforeExpires());
    }
    if (timerConfigurationType.getBlacklistRenewal() != null)
    {
      timerConfigModelBuilder.blackListRenewalLength(timerConfigurationType.getBlacklistRenewal().getLength());
      timerConfigModelBuilder.blackListRenewalUnit(timerConfigurationType.getBlacklistRenewal().getUnit());
    }
    if (timerConfigurationType.getMasterAndDefectListRenewal() != null)
    {
      timerConfigModelBuilder.masterDefectListRenewalLength(timerConfigurationType.getMasterAndDefectListRenewal()
                                                                                  .getLength());
      timerConfigModelBuilder.masterDefectListRenewalUnit(timerConfigurationType.getMasterAndDefectListRenewal()
                                                                                .getUnit());
    }
    if (timerConfigurationType.getCrlRenewal() != null)
    {
      timerConfigModelBuilder.crlRenewalLength(timerConfigurationType.getCrlRenewal().getLength());
      timerConfigModelBuilder.crlRenewalUnit(timerConfigurationType.getCrlRenewal().getUnit());
    }
    return timerConfigModelBuilder.build();
  }

  private TimerConfigurationType toConfigType(TimerConfigModel timerConfigModel)
  {
    return new TimerConfigurationType(new TimerTypeCertRenewal(timerConfigModel.getCvcRenewalLength(),
                                                               timerConfigModel.getCvcRenewalUnit(),
                                                               timerConfigModel.getHoursRefreshCvcBeforeExpiration()),
                                      new TimerType(timerConfigModel.getBlackListRenewalLength(),
                                                    timerConfigModel.getBlackListRenewalUnit()),
                                      new TimerType(timerConfigModel.getMasterDefectListRenewalLength(),
                                                    timerConfigModel.getMasterDefectListRenewalUnit()),
                                      new TimerType(timerConfigModel.getCrlRenewalLength(),
                                                    timerConfigModel.getCrlRenewalUnit()));
  }

  private void setDefaultTimerValues(TimerConfigurationType timerConfigurationType)
  {
    if (timerConfigurationType.getCertRenewal() == null)
    {
      timerConfigurationType.setCertRenewal(new TimerTypeCertRenewal(1, TimerUnit.HOURS, 20));
    }
    if (timerConfigurationType.getBlacklistRenewal() == null)
    {
      timerConfigurationType.setBlacklistRenewal(new TimerType(15, TimerUnit.MINUTES));
    }
    if (timerConfigurationType.getMasterAndDefectListRenewal() == null)
    {
      timerConfigurationType.setMasterAndDefectListRenewal(new TimerType(2, TimerUnit.HOURS));
    }
    if (timerConfigurationType.getCrlRenewal() == null)
    {
      timerConfigurationType.setCrlRenewal(new TimerType(2, TimerUnit.HOURS));
    }
  }
}

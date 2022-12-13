package de.governikus.eumw.poseidas.config.validation;

import java.util.List;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

import org.springframework.stereotype.Component;

import de.governikus.eumw.config.EidasMiddlewareConfig;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationService;
import lombok.RequiredArgsConstructor;


/**
 * This class belongs to {@link DvcaConfigNameExists}
 */
@Component
@RequiredArgsConstructor
public class DvcaConfigNameExistsValidator implements ConstraintValidator<DvcaConfigNameExists, String>
{

  private final ConfigurationService configurationService;

  @Override
  public void initialize(DvcaConfigNameExists certificateNameExists)
  {
    // NOOP
  }

  @Override
  public boolean isValid(String value, ConstraintValidatorContext context)
  {
    return value != null && configurationService.getConfiguration()
                                                .map(EidasMiddlewareConfig::getEidConfiguration)
                                                .map(EidasMiddlewareConfig.EidConfiguration::getDvcaConfiguration)
                                                .orElse(List.of())
                                                .parallelStream()
                                                .anyMatch(c -> c.getName().equals(value));
  }


}

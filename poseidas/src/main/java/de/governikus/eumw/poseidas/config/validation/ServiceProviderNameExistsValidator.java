package de.governikus.eumw.poseidas.config.validation;

import java.util.List;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

import org.springframework.stereotype.Component;

import de.governikus.eumw.config.EidasMiddlewareConfig;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationService;
import lombok.RequiredArgsConstructor;


/**
 * This class belongs to {@link ServiceProviderNameExists}
 */
@Component
@RequiredArgsConstructor
public class ServiceProviderNameExistsValidator implements ConstraintValidator<ServiceProviderNameExists, String>
{

  private final ConfigurationService configurationService;

  @Override
  public void initialize(ServiceProviderNameExists certificateNameExists)
  {
    // NOOP
  }

  @Override
  public boolean isValid(String value, ConstraintValidatorContext context)
  {
    return value != null && configurationService.getConfiguration()
                                                .map(EidasMiddlewareConfig::getEidConfiguration)
                                                .map(EidasMiddlewareConfig.EidConfiguration::getServiceProvider)
                                                .orElse(List.of())
                                                .parallelStream()
                                                .anyMatch(c -> c.getName().equals(value));
  }


}

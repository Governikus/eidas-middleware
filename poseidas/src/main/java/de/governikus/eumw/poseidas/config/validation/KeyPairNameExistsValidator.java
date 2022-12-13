package de.governikus.eumw.poseidas.config.validation;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Component;

import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationService;
import lombok.RequiredArgsConstructor;


/**
 * This class belongs to {@link KeyPairNameExists}
 */
@Component
@RequiredArgsConstructor
public class KeyPairNameExistsValidator implements ConstraintValidator<KeyPairNameExists, String>
{

  private final ConfigurationService configurationService;

  @Override
  public void initialize(KeyPairNameExists certificateNameExists)
  {
    // NOOP
  }

  @Override
  public boolean isValid(String value, ConstraintValidatorContext context)
  {
    // Null or blank value should be checked by a different annotation
    if (StringUtils.isBlank(value))
    {
      return true;
    }
    return configurationService.getKeyPairTypes().parallelStream().anyMatch(c -> c.getName().equals(value));
  }


}

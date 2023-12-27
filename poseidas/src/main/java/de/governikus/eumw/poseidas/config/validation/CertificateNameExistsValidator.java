package de.governikus.eumw.poseidas.config.validation;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Component;

import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationService;
import lombok.RequiredArgsConstructor;


/**
 * This class belongs to {@link CertificateNameExists}
 */
@Component
@RequiredArgsConstructor
public class CertificateNameExistsValidator implements ConstraintValidator<CertificateNameExists, String>
{

  private final ConfigurationService configurationService;

  @Override
  public void initialize(CertificateNameExists certificateNameExists)
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
    return configurationService.getCertificateTypes().parallelStream().anyMatch(c -> c.getName().equals(value));
  }


}

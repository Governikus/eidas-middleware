package de.governikus.eumw.poseidas.config.model.forms;

import javax.validation.constraints.NotBlank;

import org.hibernate.validator.constraints.URL;

import de.governikus.eumw.poseidas.config.validation.CertificateNameExists;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;


/**
 * Model to hold the configuration of the DVCA configuration
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
public class DvcaConfigModel
{

  @CertificateNameExists
  @NotBlank(message = "May not be empty")
  private String serverSSLCertificateName;

  @CertificateNameExists
  @NotBlank(message = "May not be empty")
  private String blackListTrustAnchorCertificateName;

  @CertificateNameExists
  @NotBlank(message = "May not be empty")
  private String masterListTrustAnchorCertificateName;

  @NotBlank(message = "May not be empty")
  private String name;

  @URL
  @NotBlank(message = "May not be empty")
  private String terminalAuthServiceUrl;

  @URL
  @NotBlank(message = "May not be empty")
  private String restrictedIdServiceUrl;

  @URL
  @NotBlank(message = "May not be empty")
  private String passiveAuthServiceUrl;

  @URL
  @NotBlank(message = "May not be empty")
  private String dvcaCertificateDescrptionServiceUrl;

  private boolean newconfig = true;
}

package de.governikus.eumw.poseidas.config.model.forms;

import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;

import org.hibernate.validator.constraints.Length;
import org.hibernate.validator.constraints.URL;

import de.governikus.eumw.poseidas.config.validation.KeyPairNameExists;
import de.governikus.eumw.poseidas.config.validation.ServiceProviderNameExists;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;


/**
 * Model to hold the configuration of the eIDAS configuration
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
public class EidasConfigModel
{

  // Basic
  @ServiceProviderNameExists
  @NotNull(message = "Has to be selected")
  private String publicServiceProviderName; // Dropdown

  @URL
  @NotEmpty(message = "May not be empty")
  private String serverUrl;

  @Length(max = 2, min = 2, message = "A Country code has exactly two characters")
  private String countryCode;

  // Metadata

  private String contactPersonCompanyName;

  private String contactPersonName;

  private String contactPersonSurname;

  private String contactPersonMail;

  private String contactPersonTel;

  private String organizationDisplayname;

  private String organizationName;

  private String organizationLanguage;

  private String organizationUrl;

  @KeyPairNameExists
  @NotEmpty(message = "Has to be selected")
  private String decryptionKeyPairName;

  @KeyPairNameExists
  @NotEmpty(message = "Has to be selected")
  private String signatureKeyPairName;

  private boolean signMetadata;
}

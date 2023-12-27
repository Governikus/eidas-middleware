package de.governikus.eumw.poseidas.config.model.forms;

import jakarta.validation.constraints.Pattern;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;


/**
 * Model to hold the configuration of the eID configuration
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
public class EidConfigModel
{

  @Pattern(regexp = "([A-Z]{1,2}(,[A-Z]{1,2})*){0,1}", message = "Empty for default or comma seperated list of one or two uppercase letters with no trailing comma or whitespaces")
  private String allowedEidMeans;
}

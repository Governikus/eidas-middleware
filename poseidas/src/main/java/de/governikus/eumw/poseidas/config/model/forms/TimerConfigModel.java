package de.governikus.eumw.poseidas.config.model.forms;

import javax.validation.constraints.NotNull;
import javax.validation.constraints.Positive;

import de.governikus.eumw.config.TimerUnit;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;


/**
 * Model to hold the configuration of the Timer configuration
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class TimerConfigModel
{

  @Positive
  @NotNull(message = "May not be empty")
  private Integer cvcRenewalLength;

  @NotNull(message = "Has to be selected")
  private TimerUnit cvcRenewalUnit;

  @Positive
  @NotNull(message = "May not be empty")
  private Integer hoursRefreshCvcBeforeExpiration;

  @Positive
  @NotNull(message = "May not be empty")
  private Integer blackListRenewalLength;

  @NotNull(message = "Has to be selected")
  private TimerUnit blackListRenewalUnit;

  @Positive
  @NotNull(message = "May not be empty")
  private Integer masterDefectListRenewalLength;

  @NotNull(message = "Has to be selected")
  private TimerUnit masterDefectListRenewalUnit;

  @Positive
  @NotNull(message = "May not be empty")
  private Integer crlRenewalLength;

  @NotNull(message = "Has to be selected")
  private TimerUnit crlRenewalUnit;
}

package de.governikus.eumw.poseidas.server.pki.entities;

import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Date;
import java.util.Locale;

import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.Lob;
import jakarta.persistence.Transient;

import lombok.Data;
import lombok.NoArgsConstructor;


/**
 * Entity to persist the history of all timers.
 *
 * @author tca
 */
@Entity
@Data
@NoArgsConstructor
public class TimerHistory
{

  public enum TimerType
  {

    BLACK_LIST_TIMER,
    CRL_RENEWAL_TIMER,
    CVC_RENEWAL_TIMER,
    GLOBAL_LIST_TIMER,
    RSC_RENEWAL,
    TLS_ENTANGLE_TIMER,
    TLS_CLIENT_RENEWAL;
  }

  @Id
  @GeneratedValue
  private Long id;

  @Enumerated(EnumType.STRING)
  private TimerType timerType;

  @Lob
  private String message;

  private Date timestamp;

  private boolean success;

  @Transient
  public static final DateTimeFormatter DATE_TIME_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss z")
                                                                               .withLocale(Locale.ENGLISH)
                                                                               .withZone(ZoneId.systemDefault());

  /**
   * Constructor to create a timer history entity.
   *
   * @param timerType The type of the timer.
   * @param message The message for the timer (success or failure message).
   * @param timestamp The {@link Date} timestamp of the timer execution.
   * @param success Boolean which shows the execution result of the timer.
   */
  public TimerHistory(TimerType timerType, String message, Date timestamp, boolean success)
  {
    this.timerType = timerType;
    this.message = message;
    this.timestamp = timestamp;
    this.success = success;
  }

  public String formatTimestamp()
  {
    return DATE_TIME_FORMATTER.format(timestamp.toInstant());
  }
}

package de.governikus.eumw.databasecleanup.entities;

import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Date;
import java.util.Locale;
import java.util.Objects;

import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.Lob;
import jakarta.persistence.Transient;

import org.hibernate.proxy.HibernateProxy;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;


/**
 * Entity to persist the history of all timers.
 *
 * @author tca
 */
@Entity
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
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
    TLS_CLIENT_RENEWAL,
    HSM_DELETION_TIMER
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

  @Override
  public final boolean equals(Object o)
  {
    if (this == o)
      return true;
    if (o == null)
      return false;
    Class<?> oEffectiveClass = o instanceof HibernateProxy hProxy
      ? hProxy.getHibernateLazyInitializer().getPersistentClass() : o.getClass();
    Class<?> thisEffectiveClass = this instanceof HibernateProxy hProxy
      ? hProxy.getHibernateLazyInitializer().getPersistentClass() : this.getClass();
    if (thisEffectiveClass != oEffectiveClass)
      return false;
    TimerHistory that = (TimerHistory)o;
    return getId() != null && Objects.equals(getId(), that.getId());
  }

  @Override
  public final int hashCode()
  {
    return this instanceof HibernateProxy hProxy ? hProxy.getHibernateLazyInitializer().getPersistentClass().hashCode()
      : getClass().hashCode();
  }
}

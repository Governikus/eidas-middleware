package de.governikus.eumw.poseidas.server.pki.caserviceaccess.logging;

import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;


/**
 * This class holds and returns the actual logger to be used when logging SOAP requests and responses.
 */
@Slf4j
@UtilityClass
public class ServiceLoggerFactory
{

  private static final String TERMINAL_AUTH_CLASS = "de.governikus.eumw.poseidas.services.terminal.auth.wsdl.v1_4_0.TerminalAuthWebService_1_4_0";

  private static final String PASSIVE_AUTH_CLASS = "de.governikus.eumw.poseidas.services.passive.auth.wsdl.v1_4_0.PassiveAuthWebService_1_4_0";

  private static final String RESTRICTED_ID_1_40_CLASS = "de.governikus.eumw.poseidas.services.restricted.id.wsdl.v1_4_0.RestrictedIdWebService_1_4_0";

  private static final String RESTRICTED_ID_1_10_CLASS = "uri.eac_pki_is_protocol._1.restrictedId.dv.EACPKIDVProtocolType";

  /**
   * The logger for TerminalAuth and CertDescription requests and responses
   */
  static final Logger TERMINAL_AUTH_LOGGER = LoggerFactory.getLogger("de.governikus.eumw.poseidas.server.pki.caserviceaccess.TerminalAuthLogger");

  /**
   * The logger for PassiveAuth requests and responses
   */
  static final Logger PASSIVE_AUTH_LOGGER = LoggerFactory.getLogger("de.governikus.eumw.poseidas.server.pki.caserviceaccess.PassiveAuthLogger");

  /**
   * The logger for RestrictedId requests and responses
   */
  static final Logger RESTRICTED_ID_LOGGER = LoggerFactory.getLogger("de.governikus.eumw.poseidas.server.pki.caserviceaccess.RestrictedIdLogger");

  /**
   * Get the logger for a SOAP client class. The logger is only returned if the class is a DVCA client class and the
   * debug level for the logger is enabled.
   *
   * @param clientClass The class for which requests and responses should be logged
   * @return The logger to be used, if the class is recognized and the debug logging level is enabled
   */
  static Optional<Logger> getLoggerForClass(Class<?> clientClass)
  {
    if (TERMINAL_AUTH_CLASS.equals(clientClass.getName()))
    {
      return TERMINAL_AUTH_LOGGER.isDebugEnabled() ? Optional.of(TERMINAL_AUTH_LOGGER) : Optional.empty();
    }
    else if (PASSIVE_AUTH_CLASS.equals(clientClass.getName()))
    {
      return PASSIVE_AUTH_LOGGER.isDebugEnabled() ? Optional.of(PASSIVE_AUTH_LOGGER) : Optional.empty();
    }
    else if (RESTRICTED_ID_1_40_CLASS.equals(clientClass.getName())
             || RESTRICTED_ID_1_10_CLASS.equals(clientClass.getName()))
    {
      return RESTRICTED_ID_LOGGER.isDebugEnabled() ? Optional.of(RESTRICTED_ID_LOGGER) : Optional.empty();
    }
    else
    {
      log.warn("Unknown SOAP client class: {}. SOAP messages for this client will not be logged.",
               clientClass.getName());
      return Optional.empty();
    }
  }
}

package de.governikus.eumw.poseidas.server.pki.caserviceaccess.logging;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.util.Optional;

import org.apache.cxf.ext.logging.event.DefaultLogEventMapper;
import org.apache.cxf.ext.logging.event.LogEvent;
import org.apache.cxf.interceptor.Fault;
import org.apache.cxf.interceptor.StaxOutInterceptor;
import org.apache.cxf.io.CacheAndWriteOutputStream;
import org.apache.cxf.message.Message;
import org.apache.cxf.phase.AbstractPhaseInterceptor;
import org.apache.cxf.phase.Phase;
import org.slf4j.Logger;

import lombok.extern.slf4j.Slf4j;


/**
 * This interceptor logs all SOAP requests and responses. There are different loggers for each DVCA endpoint type.
 */
@Slf4j
public class MessageLoggingInterceptor extends AbstractPhaseInterceptor<Message>
{

  /**
   * Create a new {@link MessageLoggingInterceptor}
   */
  public MessageLoggingInterceptor()
  {
    super(Phase.PRE_STREAM);
    addBefore(StaxOutInterceptor.class.getName());
  }

  @Override
  public void handleMessage(Message message) throws Fault
  {
    // Check if the client class should be logged
    Class<?> clientClass = (Class<?>)message.getExchange().getService().get("endpoint.class");
    Optional<Logger> optionalLogger = ServiceLoggerFactory.getLoggerForClass(clientClass);
    if (optionalLogger.isEmpty())
    {
      return;
    }

    // log the message depending on the type of message
    if (message.getContentFormats().contains(OutputStream.class))
    {
      handleRequestLogging(message);
    }
    else if (message.getContentFormats().contains(InputStream.class))
    {
      handleResponseLogging(message);
    }
  }

  private static void handleResponseLogging(Message message)
  {
    try
    {
      // Get general information about the response
      LogEvent event = new DefaultLogEventMapper().map(message);

      // Get the payload
      String encoding = (String)message.get(Message.ENCODING);
      byte[] bytes = message.getContent(InputStream.class).readAllBytes();
      event.setPayload(new String(bytes, encoding == null ? Charset.defaultCharset().name() : encoding));

      // Prepare the information to be logged
      Class<?> clientClass = (Class<?>)message.getExchange().getService().get("endpoint.class");
      LogInformation logInformation = new LogInformation(event.getAddress(), event.getType().name(), clientClass,
                                                         message.getExchange()
                                                                .getBindingOperationInfo()
                                                                .getOperationInfo()
                                                                .getName()
                                                                .getLocalPart(),
                                                         event.getPayload());

      // Log the information
      ServiceLoggerFactory.getLoggerForClass(clientClass).orElseThrow().debug(logInformation.toString());

      // Recreate the original input stream of the response
      message.setContent(InputStream.class, new ByteArrayInputStream(bytes));
    }
    catch (IOException e)
    {
      log.warn("Cannot read bytes of the SOAP response", e);
    }
  }

  private static void handleRequestLogging(Message message)
  {
    final OutputStream os = message.getContent(OutputStream.class);
    if (os != null)
    {
      // To log requests, a special callback mechanism must be used to log the data when the request is actually sent.
      LoggingCallback callback = new LoggingCallback(message, os);
      final CacheAndWriteOutputStream cachedOutputStream = new CacheAndWriteOutputStream(os);
      cachedOutputStream.registerCallback(callback);
      message.setContent(OutputStream.class, cachedOutputStream);
    }
    else
    {
      log.warn("Cannot log the SOAP request, unexpected content implementation");
    }
  }
}

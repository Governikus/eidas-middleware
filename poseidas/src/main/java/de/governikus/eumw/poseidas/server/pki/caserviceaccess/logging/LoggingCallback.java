package de.governikus.eumw.poseidas.server.pki.caserviceaccess.logging;

import java.io.OutputStream;

import org.apache.cxf.common.util.StringUtils;
import org.apache.cxf.ext.logging.event.DefaultLogEventMapper;
import org.apache.cxf.ext.logging.event.LogEvent;
import org.apache.cxf.io.CachedOutputStream;
import org.apache.cxf.io.CachedOutputStreamCallback;
import org.apache.cxf.message.Message;

import lombok.extern.slf4j.Slf4j;


/**
 * This class logs outgoing SOAP requests to the DVCA. It does so by caching the output stream of the request and
 * logging the data when the request is sent. <br>
 * This implementation uses the same mechanism as {@link org.apache.cxf.ext.logging.LoggingOutInterceptor} to get the
 * data to be logged, but the actual logging is performed differently.
 */
@Slf4j
class LoggingCallback implements CachedOutputStreamCallback
{

  private final Message message;

  private final OutputStream origStream;

  /**
   * Create a new instance of the {@link LoggingCallback}
   *
   * @param message The message to be logged
   * @param os The content of the message as an output stream
   */
  public LoggingCallback(Message message, OutputStream os)
  {
    this.message = message;
    this.origStream = os;
  }

  @Override
  public void onFlush(CachedOutputStream cos)
  {

  }

  @Override
  public void onClose(CachedOutputStream cos)
  {
    // Prepare the logging information
    Class<?> clientClass = (Class<?>)message.getExchange().getService().get("endpoint.class");
    final LogEvent event = new DefaultLogEventMapper().map(message);
    copyPayload(cos, event);
    LogInformation logInformation = new LogInformation(event.getAddress(), event.getType().name(), clientClass,
                                                       message.getExchange()
                                                              .getBindingOperationInfo()
                                                              .getOperationInfo()
                                                              .getName()
                                                              .getLocalPart(),
                                                       event.getPayload());

    // Log the information
    ServiceLoggerFactory.getLoggerForClass(clientClass).orElseThrow().debug(logInformation.toString());

    // Clear the cache and reset the original output stream
    try
    {
      // empty out the cache
      cos.lockOutputStream();
      cos.resetOut(null, false);
    }
    catch (Exception ex)
    {
      if (log.isDebugEnabled())
      {
        log.debug(ex.getMessage());
      }
      // ignore
    }
    message.setContent(OutputStream.class, origStream);
  }

  private void copyPayload(CachedOutputStream cos, final LogEvent event)
  {
    try
    {
      String encoding = (String)message.get(Message.ENCODING);
      StringBuilder payload = new StringBuilder();
      writePayload(payload, cos, encoding);
      event.setPayload(payload.toString());
      event.setTruncated(false);
    }
    catch (Exception ex)
    {
      log.debug("Cannot copy the payload for the SOAP request", ex);
    }
  }

  protected void writePayload(StringBuilder builder, CachedOutputStream cos, String encoding) throws Exception
  {
    if (StringUtils.isEmpty(encoding))
    {
      cos.writeCacheTo(builder);
    }
    else
    {
      cos.writeCacheTo(builder, encoding);
    }
  }
}

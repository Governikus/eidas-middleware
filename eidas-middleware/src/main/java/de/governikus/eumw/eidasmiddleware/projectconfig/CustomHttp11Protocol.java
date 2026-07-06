package de.governikus.eumw.eidasmiddleware.projectconfig;

import org.apache.coyote.http11.AbstractHttp11Protocol;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.net.NioChannel;

import lombok.extern.slf4j.Slf4j;


/**
 * An HTTP 1.1 protocol implementation overwrite to inject the {@link NioEndpointExtension} used by the
 * {@link PortCreator}
 */
@Slf4j
public class CustomHttp11Protocol extends AbstractHttp11Protocol<NioChannel>
{

  public static final String PROTOCOL = CustomHttp11Protocol.class.getName();

  private static final Log LOG = LogFactory.getLog(CustomHttp11Protocol.class);

  public CustomHttp11Protocol()
  {
    super(new NioEndpointExtension());

  }

  @Override
  protected Log getLog()
  {
    return LOG;
  }


  @Override
  protected String getNamePrefix()
  {
    if (isSSLEnabled())
    {
      return "https-" + getSslImplementationShortName() + "-nio";
    }
    else
    {
      return "http-nio";
    }
  }

}

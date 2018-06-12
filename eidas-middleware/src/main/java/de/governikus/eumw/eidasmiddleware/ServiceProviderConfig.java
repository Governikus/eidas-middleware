/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.eidasmiddleware;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.cert.CertificateException;

import org.opensaml.core.config.InitializationException;
import org.opensaml.core.xml.io.UnmarshallingException;

import de.governikus.eumw.eidascommon.ErrorCodeException;
import de.governikus.eumw.eidasmiddleware.eid.RequestingServiceProvider;
import de.governikus.eumw.eidasstarterkit.EidasMetadataNode;
import de.governikus.eumw.eidasstarterkit.EidasSaml;
import lombok.extern.slf4j.Slf4j;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.xml.XMLParserException;


/**
 * Loads the first metadata.xml file in the configured service provider folder
 *
 * @author hohnholt
 */
@Slf4j
public class ServiceProviderConfig
{
  private static ServiceProviderConfig config = null;

  private RequestingServiceProvider firstProvider = null;

  private ServiceProviderConfig()
  {
    File[] files = ConfigHolder.getProviderConfigDir()
                               .listFiles(pathname -> pathname.getAbsolutePath().endsWith(".xml"));

    if (files.length < 1)
    {
      log.error("Could not found any service provider config in "
                + ConfigHolder.getProviderConfigDir().getAbsolutePath());
      return;
    }

    try (FileInputStream is = new FileInputStream(files[0]))
    {
      EidasMetadataNode checkMeta = EidasSaml.parseMetaDataNode(is, ConfigHolder.getMetadataSignatureCert());
      RequestingServiceProvider rsp = new RequestingServiceProvider(checkMeta.getEntityId());
      rsp.setAssertionConsumerURL(checkMeta.getPostEndpoint());
      rsp.setEncryptionCert(checkMeta.getEncCert());
      rsp.setSignatureCert(checkMeta.getSigCert());
      firstProvider = rsp;
    }
    catch (IOException | CertificateException | XMLParserException | UnmarshallingException
      | InitializationException | ComponentInitializationException | ErrorCodeException e)
    {
      log.error("Cannot parse connector metadata {}", files[0], e);
      throw new IllegalStateException("Cannot parse connector metadata " + files[0], e);
    }
  }

  static ServiceProviderConfig getConfig()
  {
    if (config == null)
    {
      config = new ServiceProviderConfig();
    }
    return config;
  }

  public static synchronized RequestingServiceProvider getFirstProvider()
  {
    return getConfig().firstProvider;
  }
}

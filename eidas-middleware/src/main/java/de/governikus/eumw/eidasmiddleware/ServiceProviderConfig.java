/*
 * Copyright (c) 2019 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
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
import java.util.HashMap;
import java.util.Map;

import org.opensaml.core.config.InitializationException;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.springframework.stereotype.Component;

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
@Component
public class ServiceProviderConfig
{

  private final ConfigHolder configHolder;

  private final Map<String, RequestingServiceProvider> allProviders = new HashMap<>();

  public ServiceProviderConfig(ConfigHolder configHolder)
  {
    this.configHolder = configHolder;
    loadMetadataFiles();
  }

  /**
   * Read and parse the files from the metadata directory, throw a {@link BadConfigurationException} if the
   * signature cannot be verified.
   */
  private final void loadMetadataFiles()
  {
    File[] files = configHolder.getProviderConfigDir()
                               .listFiles(pathname -> pathname.getAbsolutePath().endsWith(".xml"));

    if (files == null || files.length < 1)
    {
      throw new BadConfigurationException("No service provider config found in "
                                          + configHolder.getProviderConfigDir().getAbsolutePath());
    }

    for ( File f : files )
    {
      try (FileInputStream is = new FileInputStream(f))
      {
        EidasMetadataNode checkMeta = EidasSaml.parseMetaDataNode(is,
                                                                  configHolder.getMetadataSignatureCert());
        RequestingServiceProvider rsp = new RequestingServiceProvider(checkMeta.getEntityId());
        rsp.setAssertionConsumerURL(checkMeta.getPostEndpoint());
        rsp.setEncryptionCert(checkMeta.getEncCert());
        rsp.setSignatureCert(checkMeta.getSigCert());
        rsp.setSectorType(checkMeta.getSpType());
        allProviders.put(rsp.getEntityID(), rsp);
      }
      catch (IOException | CertificateException | XMLParserException | UnmarshallingException
        | InitializationException | ComponentInitializationException | ErrorCodeException e)
      {
        throw new BadConfigurationException("Cannot parse metadata file: " + f.getName(), e);
      }
    }
  }

  /**
   * Return the service provider for the given entityID or null if not found
   */
  public RequestingServiceProvider getProviderByEntityID(String entityID)
  {
    return allProviders.get(entityID);
  }
}

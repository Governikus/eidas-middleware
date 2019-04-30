/*
 * Copyright (c) 2019 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.eidasmiddleware.handler;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.DataFormatException;

import javax.xml.bind.DatatypeConverter;

import de.governikus.eumw.eidasmiddleware.ConfigHolder;
import de.governikus.eumw.eidasmiddleware.RequestProcessingException;
import de.governikus.eumw.eidasmiddleware.RequestSession;
import de.governikus.eumw.eidasmiddleware.ServiceProviderConfig;
import de.governikus.eumw.eidasmiddleware.SessionStore;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.springframework.stereotype.Component;
import org.xml.sax.SAXException;

import de.governikus.eumw.eidascommon.ContextPaths;
import de.governikus.eumw.eidascommon.ErrorCode;
import de.governikus.eumw.eidascommon.ErrorCodeException;
import de.governikus.eumw.eidascommon.HttpRedirectUtils;
import de.governikus.eumw.eidascommon.Utils;
import de.governikus.eumw.eidasmiddleware.eid.RequestingServiceProvider;
import de.governikus.eumw.eidasstarterkit.EidasRequest;
import de.governikus.eumw.eidasstarterkit.EidasRequestSectorType;
import de.governikus.eumw.eidasstarterkit.EidasSaml;
import lombok.extern.slf4j.Slf4j;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.xml.XMLParserException;


/**
 * Process incoming authn requests
 */
@Slf4j
@Component
public class RequestHandler
{

  public static final String CANNOT_PARSE_SAML_REQUEST = "Cannot parse SAML Request";

  /**
   * store the incoming requests
   */
  private final SessionStore store;

  /**
   * access the config for the different service providers
   */
  private final ServiceProviderConfig serviceProviderConfig;

  /**
   * access the config of the middleware
   */
  private final ConfigHolder configHolder;

  /**
   * Default constructor with DI
   */
  public RequestHandler(SessionStore store,
                        ConfigHolder configHolder,
                        ServiceProviderConfig serviceProviderConfig)
  {
    this.store = store;
    this.configHolder = configHolder;
    this.serviceProviderConfig = serviceProviderConfig;
  }

  /**
   * Handles the SAML request.
   *
   * @param samlRequestBase64 The SAMLRequest parameter from the incoming request
   * @param isPost <code>true</code> for HTTP POST, <code>false</code> for HTTP GET
   */
  String handleSAMLRequest(String samlRequestBase64, boolean isPost)
  {
    return handleSAMLRequest(null, samlRequestBase64, isPost);
  }

  /**
   * Handles the SAML request.
   *
   * @param relayState The relayState parameter from the incoming request
   * @param samlRequestBase64 The SAMLRequest parameter from the incoming request
   * @param isPost <code>true</code> for HTTP POST, <code>false</code> for HTTP GET
   * @return The stored sessionID that will be requested at the TcToken endpoint
   */
  public String handleSAMLRequest(String relayState, String samlRequestBase64, boolean isPost)
  {
    EidasRequest eidasReq;
    try
    {
      if (samlRequestBase64 == null)
      {
        throw new ErrorCodeException(ErrorCode.ILLEGAL_REQUEST_SYNTAX,
                                     "Query Parameter 'SAMLRequest' is missing");
      }

      byte[] samlRequest = getSAMLRequestBytes(isPost, samlRequestBase64);

      log.trace("Incoming SAML request: {}", new String(samlRequest, StandardCharsets.UTF_8));

      // Validate and parse the SAML request
      eidasReq = parseSAMLRequest(samlRequest);

      EidasRequestSectorType metadataSectorType = serviceProviderConfig.getProviderByEntityID(eidasReq.getIssuer())
                                                                       .getSectorType();
      EidasRequestSectorType requestSectorType = eidasReq.getSectorType();
      if (metadataSectorType == null && requestSectorType == null)
      {
        throw new ErrorCodeException(ErrorCode.ILLEGAL_REQUEST_SYNTAX,
                                     "sector type neither given in request nor in metadata");
      }
      if (metadataSectorType != null && requestSectorType != null)
      {
        throw new ErrorCodeException(ErrorCode.ILLEGAL_REQUEST_SYNTAX,
                                     "sector type must not be given twice (in request and in metadata)");
      }
      if (metadataSectorType != null)
      {
        eidasReq.setSectorType(metadataSectorType);
      }

      store.insert(new RequestSession(relayState, eidasReq));

      // Check that the consumer URL is equal with the connector's metadata
      if (!Utils.isNullOrEmpty(eidasReq.getAuthnRequest().getAssertionConsumerServiceURL())
          && !serviceProviderConfig.getProviderByEntityID(eidasReq.getIssuer())
                                   .getAssertionConsumerURL()
                                   .equals(eidasReq.getAuthnRequest().getAssertionConsumerServiceURL()))
      {
        throw new ErrorCodeException(ErrorCode.WRONG_DESTINATION,
                                     "Given AssertionConsumerServiceURL ist not valid!");
      }

      return eidasReq.getId();
    }
    catch (Exception e)
    {
      throw new RequestProcessingException(CANNOT_PARSE_SAML_REQUEST, e);
    }
  }

  /**
   * Validate and parse the SAML request
   *
   * @return the parsed {@link EidasRequest}
   */
  private EidasRequest parseSAMLRequest(byte[] samlRequest)
    throws IOException, SAXException, ErrorCodeException, UnmarshallingException, InitializationException,
    XMLParserException, ComponentInitializationException
  {
    try (InputStream is = new ByteArrayInputStream(samlRequest))
    {
      EidasSaml.validateXMLRequest(is, true);
      EidasRequest request = EidasSaml.parseRequest(is);

      RequestingServiceProvider requestingServiceProvider = serviceProviderConfig.getProviderByEntityID(request.getIssuer());
      if (requestingServiceProvider == null)
      {
        throw new ErrorCodeException(ErrorCode.UNKNOWN_PROVIDER, request.getIssuer());
      }
      List<X509Certificate> authors = new ArrayList<>();
      authors.add(requestingServiceProvider.getSignatureCert());
      EidasSaml.verifyRequest(request, authors);
      return request;
    }
  }

  /**
   * Return the SAML request byte array from the base64 encoded string
   */
  private byte[] getSAMLRequestBytes(boolean isPost, String samlRequestBase64)
    throws DataFormatException, ErrorCodeException
  {
    byte[] samlRequest;

    if (isPost)
    {
      samlRequest = DatatypeConverter.parseBase64Binary(samlRequestBase64);
    }
    else
    {
      samlRequest = HttpRedirectUtils.inflate(samlRequestBase64);
    }

    if (samlRequest == null)
    {
      log.warn("cannot parse base64 encoded SAML request: {}", samlRequestBase64);
      throw new ErrorCodeException(ErrorCode.ILLEGAL_REQUEST_SYNTAX,
                                   "cannot parse base64 encoded SAML request");
    }
    return samlRequest;
  }

  /**
   * Return the URL to the TcToken endpoint with the given sessionId
   */
  public String getTcTokenURL(String sessionId)
  {
    return configHolder.getServerURLWithContextPath() + ContextPaths.TC_TOKEN + "?sessionID=" + sessionId;
  }
}

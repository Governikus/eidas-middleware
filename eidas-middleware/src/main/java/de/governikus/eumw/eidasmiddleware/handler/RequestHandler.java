/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.eidasmiddleware.handler;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.zip.DataFormatException;

import javax.xml.bind.DatatypeConverter;

import org.apache.commons.lang3.StringUtils;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.core.xml.io.UnmarshallerFactory;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.springframework.stereotype.Component;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

import de.governikus.eumw.eidascommon.ContextPaths;
import de.governikus.eumw.eidascommon.ErrorCode;
import de.governikus.eumw.eidascommon.ErrorCodeException;
import de.governikus.eumw.eidascommon.ErrorCodeWithResponseException;
import de.governikus.eumw.eidascommon.HttpRedirectUtils;
import de.governikus.eumw.eidascommon.Utils;
import de.governikus.eumw.eidasmiddleware.RequestProcessingException;
import de.governikus.eumw.eidasmiddleware.eid.RequestingServiceProvider;
import de.governikus.eumw.eidasmiddleware.entities.RequestSession;
import de.governikus.eumw.eidasmiddleware.repositories.RequestSessionRepository;
import de.governikus.eumw.eidasstarterkit.EidasRequest;
import de.governikus.eumw.eidasstarterkit.EidasSaml;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationException;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationService;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;
import net.shibboleth.utilities.java.support.xml.XMLParserException;
import se.litsec.eidas.opensaml.ext.SPTypeEnumeration;


/**
 * Process incoming authn requests
 */
@Slf4j
@Component
@AllArgsConstructor(access = AccessLevel.PACKAGE)
public class RequestHandler
{

  public static final String CANNOT_PARSE_SAML_REQUEST = "Cannot parse SAML Request";

  /**
   * store the incoming requests
   */
  private final RequestSessionRepository requestSessionRepository;

  /**
   * access the config of the middleware
   */
  private final ConfigurationService configurationService;


  /**
   * Handles the SAML request.
   *
   * @param samlRequestBase64 The SAMLRequest parameter from the incoming request
   * @param isPost <code>true</code> for HTTP POST, <code>false</code> for HTTP GET
   */
  EidasRequest handleSAMLRequest(String samlRequestBase64, boolean isPost) throws ErrorCodeWithResponseException
  {
    return handleSAMLRequest(null, samlRequestBase64, isPost);
  }

  /**
   * Handles the SAML request.
   *
   * @param relayState The relayState parameter from the incoming request
   * @param samlRequestBase64 The SAMLRequest parameter from the incoming request
   * @param isPost <code>true</code> for HTTP POST, <code>false</code> for HTTP GET
   * @return The eIDAS request with the stored sessionID for the TcToken endpoint
   */
  public EidasRequest handleSAMLRequest(String relayState, String samlRequestBase64, boolean isPost)
    throws ErrorCodeWithResponseException
  {
    EidasRequest eidasReq;
    try
    {
      if (samlRequestBase64 == null)
      {
        throw new ErrorCodeException(ErrorCode.ILLEGAL_REQUEST_SYNTAX, "Query Parameter 'SAMLRequest' is missing");
      }

      byte[] samlRequest = getSAMLRequestBytes(isPost, samlRequestBase64);

      log.trace("Incoming SAML request: {}", new String(samlRequest, StandardCharsets.UTF_8));

      // Validate and parse the SAML request
      eidasReq = parseSAMLRequest(samlRequest);

      SPTypeEnumeration metadataSectorType = configurationService.getProviderByEntityID(eidasReq.getIssuer())
                                                                 .getSectorType();
      SPTypeEnumeration requestSectorType = eidasReq.getSectorType();
      if (metadataSectorType == null && requestSectorType == null)
      {
        throw new ErrorCodeWithResponseException(ErrorCode.ILLEGAL_REQUEST_SYNTAX, eidasReq.getIssuer(),
                                                 eidasReq.getId(),
                                                 "Sector type neither given in request nor in metadata");
      }
      if (metadataSectorType != null && requestSectorType != null)
      {
        throw new ErrorCodeWithResponseException(ErrorCode.ILLEGAL_REQUEST_SYNTAX, eidasReq.getIssuer(),
                                                 eidasReq.getId(), "Sector type is present in metadata and request");
      }
      if (metadataSectorType != null)
      {
        eidasReq.setSectorType(metadataSectorType);
      }

      requestSessionRepository.save(new RequestSession(relayState, eidasReq, getReqProviderName(eidasReq)));

      // Check that the consumer URL is equal with the connector's metadata
      if (!Utils.isNullOrEmpty(eidasReq.getAuthnRequest().getAssertionConsumerServiceURL())
          && !configurationService.getProviderByEntityID(eidasReq.getIssuer())
                                  .getAssertionConsumerURL()
                                  .equals(eidasReq.getAuthnRequest().getAssertionConsumerServiceURL()))
      {
        throw new ErrorCodeException(ErrorCode.WRONG_DESTINATION, "Given AssertionConsumerServiceURL ist not valid!");
      }
      return eidasReq;
    }
    catch (ErrorCodeWithResponseException e)
    {
      throw e;
    }
    catch (Exception e)
    {
      throw new RequestProcessingException(CANNOT_PARSE_SAML_REQUEST, e);
    }
  }

  /**
   * Return the service provider name in case the request is of SPType PRIVATE
   *
   * @param eidasRequest The incoming SAML request
   * @return The name of the internal service provider to be used or <code>null</code> if the request is of SPType
   *         PUBLIC
   * @throws ErrorCodeWithResponseException In case no service provider name is given in the request or the name is
   *           unknown
   */
  private String getReqProviderName(EidasRequest eidasRequest) throws ErrorCodeWithResponseException
  {
    String reqProviderName = null;
    if (eidasRequest.getSectorType() == SPTypeEnumeration.PRIVATE)
    {
      if (eidasRequest.getRequesterId() != null)
      {
        reqProviderName = eidasRequest.getRequesterId();
      }
      // eIDAS specs 1.1 defined providerName as the source for the service provider and is used here for backwards
      // compatibility
      else if (eidasRequest.getProviderName() != null)
      {
        reqProviderName = eidasRequest.getProviderName();
      }
      else
      {
        // No name of service provider in requesterId or providerName, aborting
        throw new ErrorCodeWithResponseException(ErrorCode.ILLEGAL_REQUEST_SYNTAX, eidasRequest.getIssuer(),
                                                 eidasRequest.getId(), "RequesterID is missing in SAML request");
      }
      final String finalReqProviderName = reqProviderName;
      if (configurationService.getConfiguration()
                              .orElseThrow(() -> new ConfigurationException("No eumw configuration present"))
                              .getEidConfiguration()
                              .getServiceProvider()
                              .stream()
                              .filter(serviceProviderType -> serviceProviderType.getName().equals(finalReqProviderName))
                              .findFirst()
                              .isEmpty())
      {
        // No service provider available with the given name
        log.debug("Received SAML request with unknown RequesterID: {}", reqProviderName);
        throw new ErrorCodeWithResponseException(ErrorCode.ILLEGAL_REQUEST_SYNTAX, eidasRequest.getIssuer(),
                                                 eidasRequest.getId(), "RequesterID is unknown");
      }
    }
    return reqProviderName;
  }

  /**
   * Validate and parse the SAML request
   *
   * @return the parsed {@link EidasRequest}
   */
  private EidasRequest parseSAMLRequest(byte[] samlRequest) throws IOException, SAXException, ErrorCodeException,
    UnmarshallingException, InitializationException, XMLParserException, ComponentInitializationException
  {
    try (InputStream is = new ByteArrayInputStream(samlRequest))
    {
      EidasSaml.validateXMLRequest(is, true);
      AuthnRequest authnRequest = getAuthnRequest(is);
      is.reset();

      // Check that the AuthnRequest is not older than one minute
      if (authnRequest.getIssueInstant() == null
          || authnRequest.getIssueInstant().isBefore(Instant.now().minus(1, ChronoUnit.MINUTES)))
      {
        throw new ErrorCodeException(ErrorCode.OUTDATED_REQUEST);
      }

      // Check that there is no RequestSession for this AuthnRequest
      String authnRequestID = authnRequest.getID();
      if (StringUtils.isBlank(authnRequestID))
      {
        throw new ErrorCodeException(ErrorCode.MISSING_REQUEST_ID);
      }
      if (requestSessionRepository.findById(authnRequestID).isPresent())
      {
        throw new ErrorCodeException(ErrorCode.DUPLICATE_REQUEST_ID, authnRequestID);
      }

      // Check the AuthnRequest signature
      String issuer = Objects.requireNonNull(authnRequest.getIssuer().getDOM()).getTextContent();
      RequestingServiceProvider requestingServiceProvider = configurationService.getProviderByEntityID(issuer);
      if (requestingServiceProvider == null)
      {
        throw new ErrorCodeException(ErrorCode.UNKNOWN_PROVIDER, issuer);
      }
      List<X509Certificate> authors = new ArrayList<>();
      authors.add(requestingServiceProvider.getSignatureCert());
      return EidasSaml.parseRequest(is, authors);
    }
  }

  private AuthnRequest getAuthnRequest(InputStream is)
    throws InitializationException, ComponentInitializationException, XMLParserException, UnmarshallingException
  {
    EidasSaml.init();
    BasicParserPool ppMgr = Utils.getBasicParserPool();
    Document inCommonMDDoc = ppMgr.parse(is);

    Element metadataRoot = inCommonMDDoc.getDocumentElement();
    UnmarshallerFactory unmarshallerFactory = XMLObjectProviderRegistrySupport.getUnmarshallerFactory();
    Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(metadataRoot);
    return (AuthnRequest)unmarshaller.unmarshall(metadataRoot);
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
      throw new ErrorCodeException(ErrorCode.ILLEGAL_REQUEST_SYNTAX, "cannot parse base64 encoded SAML request");
    }
    return samlRequest;
  }

  /**
   * Return the URL to the TcToken endpoint with the given sessionId
   */
  public String getTcTokenURL(String sessionId)
  {
    return configurationService.getServerURLWithEidasContextPath() + ContextPaths.TC_TOKEN + "?sessionID=" + sessionId;
  }
}

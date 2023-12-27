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

import jakarta.xml.bind.DatatypeConverter;

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
import de.governikus.eumw.eidascommon.CryptoAlgUtil;
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
import se.swedenconnect.opensaml.eidas.ext.SPTypeEnumeration;


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


  public EidasRequest handleSAMLRedirectRequest(String samlRequest, String relayState, String sigAlg, String signature)
    throws ErrorCodeWithResponseException
  {
    try
    {
      byte[] samlRequestBytes = HttpRedirectUtils.inflate(samlRequest);

      log.trace("Incoming SAML request: {}", new String(samlRequestBytes, StandardCharsets.UTF_8));

      // Pre-validate the request
      AuthnRequest authnRequest = preValidateSAMLRequest(samlRequestBytes);

      // Verify the signature algorithm is allowed
      CryptoAlgUtil.verifySignatureAlgorithm(sigAlg);

      // Verify the signature of the SAML request
      RequestingServiceProvider serviceProvider = getRequestingServiceProvider(authnRequest);
      HttpRedirectUtils.verifyQueryString(samlRequest,
                                          relayState,
                                          sigAlg,
                                          signature,
                                          serviceProvider.getSignatureCert());

      // Parse the SAML request
      EidasRequest eidasReq = EidasSaml.parseRequest(new ByteArrayInputStream(samlRequestBytes), null);

      // post-validate the request and save it in the request session repository
      postValidateAndSaveSAMLRequest(relayState, serviceProvider, eidasReq);
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
   * Handles the SAML request.
   *
   * @param relayState The relayState parameter from the incoming request
   * @param samlRequestBase64 The SAMLRequest parameter from the incoming request
   * @return The eIDAS request with the stored sessionID for the TcToken endpoint
   */
  public EidasRequest handleSAMLPostRequest(String relayState, String samlRequestBase64)
    throws ErrorCodeWithResponseException
  {
    try
    {
      if (samlRequestBase64 == null)
      {
        throw new ErrorCodeException(ErrorCode.ILLEGAL_REQUEST_SYNTAX, "Query Parameter 'SAMLRequest' is missing");
      }

      byte[] samlRequest = DatatypeConverter.parseBase64Binary(samlRequestBase64);

      log.trace("Incoming SAML request: {}", new String(samlRequest, StandardCharsets.UTF_8));

      // Pre-validate the request
      AuthnRequest authnRequest = preValidateSAMLRequest(samlRequest);

      // Verify the hash and signature algorithm are allowed
      CryptoAlgUtil.verifyDigestAndSignatureAlgorithm(authnRequest.getSignature());

      // Verify the signature and parse the SAML request
      List<X509Certificate> authors = new ArrayList<>();
      RequestingServiceProvider serviceProvider = getRequestingServiceProvider(authnRequest);
      authors.add(serviceProvider.getSignatureCert());
      EidasRequest eidasReq = EidasSaml.parseRequest(new ByteArrayInputStream(samlRequest), authors);

      // post-validate the request and save it in the request session repository
      postValidateAndSaveSAMLRequest(relayState, serviceProvider, eidasReq);
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
   * Performs these pre validations for the SAML request:
   * <ul>
   * <li>Validate the XML Schema</li>
   * <li>Check that the AuthnRequest is not older than one minute</li>
   * <li>Check that there is no RequestSession for this AuthnRequest</li>
   * </ul>
   * <b>No signature validation is performed.</b>
   *
   * @return The parsed SAML request.
   * @throws Exception when any of these checks fail
   */
  private AuthnRequest preValidateSAMLRequest(byte[] samlRequest) throws IOException, SAXException, ErrorCodeException,
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

      return authnRequest;

    }
  }

  private RequestingServiceProvider getRequestingServiceProvider(AuthnRequest authnRequest) throws ErrorCodeException
  {
    String issuer = Objects.requireNonNull(authnRequest.getIssuer().getDOM()).getTextContent();
    RequestingServiceProvider requestingServiceProvider = configurationService.getProviderByEntityID(issuer);
    if (requestingServiceProvider == null)
    {
      throw new ErrorCodeException(ErrorCode.UNKNOWN_PROVIDER, issuer);
    }
    return requestingServiceProvider;
  }

  private void postValidateAndSaveSAMLRequest(String relayState,
                                              RequestingServiceProvider serviceProvider,
                                              EidasRequest eidasReq)
    throws ErrorCodeException
  {
    // Check that the sector type is specified in either the metadata or the request
    SPTypeEnumeration metadataSectorType = serviceProvider.getSectorType();
    SPTypeEnumeration requestSectorType = eidasReq.getSectorType();
    if (metadataSectorType == null && requestSectorType == null)
    {
      throw new ErrorCodeWithResponseException(ErrorCode.ILLEGAL_REQUEST_SYNTAX, eidasReq.getIssuer(), eidasReq.getId(),
                                               "Sector type neither given in request nor in metadata");
    }
    if (metadataSectorType != null && requestSectorType != null)
    {
      throw new ErrorCodeWithResponseException(ErrorCode.ILLEGAL_REQUEST_SYNTAX, eidasReq.getIssuer(), eidasReq.getId(),
                                               "Sector type is present in metadata and request");
    }
    if (metadataSectorType != null)
    {
      eidasReq.setSectorType(metadataSectorType);
    }

    // Check that the consumer URL is equal with the connector's metadata
    if (!Utils.isNullOrEmpty(eidasReq.getAuthnRequest().getAssertionConsumerServiceURL())
        && !configurationService.getProviderByEntityID(eidasReq.getIssuer())
                                .getAssertionConsumerURL()
                                .equals(eidasReq.getAuthnRequest().getAssertionConsumerServiceURL()))
    {
      throw new ErrorCodeException(ErrorCode.WRONG_DESTINATION, "Given AssertionConsumerServiceURL ist not valid!");
    }

    // Save the SAML request for later use
    requestSessionRepository.save(new RequestSession(relayState, eidasReq, getReqProviderName(eidasReq)));
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
   * Return the URL to the TcToken endpoint with the given sessionId
   */
  public String getTcTokenURL(String sessionId)
  {
    return configurationService.getServerURLWithEidasContextPath() + ContextPaths.TC_TOKEN + "?sessionID=" + sessionId;
  }
}

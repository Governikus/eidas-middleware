/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.eidasstarterkit;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactoryConfigurationError;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.opensaml.core.xml.Namespace;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.core.xml.io.UnmarshallerFactory;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.saml.ext.reqattr.RequestedAttributes;
import org.opensaml.saml.ext.reqattr.impl.RequestedAttributesBuilder;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Extensions;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameIDPolicy;
import org.opensaml.saml.saml2.core.NameIDType;
import org.opensaml.saml.saml2.core.RequestedAuthnContext;
import org.opensaml.saml.saml2.core.RequesterID;
import org.opensaml.saml.saml2.core.Scoping;
import org.opensaml.saml.saml2.core.impl.AuthnContextClassRefBuilder;
import org.opensaml.saml.saml2.core.impl.AuthnRequestBuilder;
import org.opensaml.saml.saml2.core.impl.AuthnRequestMarshaller;
import org.opensaml.saml.saml2.core.impl.ExtensionsBuilder;
import org.opensaml.saml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml.saml2.core.impl.NameIDPolicyBuilder;
import org.opensaml.saml.saml2.core.impl.RequestedAuthnContextBuilder;
import org.opensaml.saml.saml2.core.impl.RequesterIDBuilder;
import org.opensaml.saml.saml2.core.impl.ScopingBuilder;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.Signer;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import de.governikus.eumw.eidascommon.ErrorCode;
import de.governikus.eumw.eidascommon.ErrorCodeException;
import de.governikus.eumw.eidascommon.ErrorCodeWithResponseException;
import de.governikus.eumw.eidascommon.Utils;
import de.governikus.eumw.eidasstarterkit.person_attributes.EidasPersonAttributes;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;
import net.shibboleth.utilities.java.support.xml.XMLParserException;
import se.litsec.eidas.opensaml.common.EidasConstants;
import se.litsec.eidas.opensaml.ext.RequestedAttribute;
import se.litsec.eidas.opensaml.ext.SPType;
import se.litsec.eidas.opensaml.ext.SPTypeEnumeration;
import se.litsec.eidas.opensaml.ext.impl.RequestedAttributeBuilder;
import se.litsec.eidas.opensaml.ext.impl.SPTypeBuilder;



/**
 * @author hohnholt
 */
@Slf4j
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class EidasRequest
{

  @Getter
  private String id;

  @Getter
  private String destination;

  @Getter
  private String issuer;

  private Instant issueInstant;

  @Getter
  @Setter
  private String providerName;

  @Getter
  private String requesterId;

  @Getter
  @Setter
  private boolean forceAuthn;

  @Getter
  @Setter
  private boolean isPassive;

  @Getter
  @Setter
  private SPTypeEnumeration sectorType;

  @Getter
  @Setter
  private EidasNameIdType nameIdPolicy = EidasNameIdType.TRANSIENT;

  @Getter
  @Setter
  private EidasLoaEnum authClassRef = EidasLoaEnum.LOA_HIGH;

  @Getter
  private TestCaseEnum testCase;

  private EidasSigner signer;

  @Getter
  private AuthnRequest authnRequest;

  @Getter
  private final Map<EidasPersonAttributes, Boolean> requestedAttributes = new HashMap<>();

  EidasRequest(String destination, String issuer, String providerName, EidasSigner signer)
  {
    this(destination, SPTypeEnumeration.PUBLIC, EidasNameIdType.TRANSIENT, EidasLoaEnum.LOA_HIGH, issuer, providerName,
         null, signer);
  }

  EidasRequest(String destination, String issuer, String providerName, EidasSigner signer, String id)
  {
    this(id, destination, SPTypeEnumeration.PUBLIC, EidasNameIdType.TRANSIENT, EidasLoaEnum.LOA_HIGH, issuer,
         providerName, null, signer);
  }

  EidasRequest(String destination,
               SPTypeEnumeration sectorType,
               EidasNameIdType nameIdPolicy,
               EidasLoaEnum loa,
               String issuer,
               String providerName,
               String requesterId,
               EidasSigner signer)
  {
    this("_" + Utils.generateUniqueID(), destination, sectorType, nameIdPolicy, loa, issuer, providerName, requesterId,
         signer);
  }

  /**
   * Creates an EidasRequest without an id and a test case. The id is automatically generated.
   *
   * @param destination the destination of the eIDAS-Request.
   * @param sectorType the sector type of the eIDAS-Request.
   * @param nameIdPolicy the nameIdPolicy of theeIDAS-Request. Can be null. The default value is
   *          {@link EidasNameIdType#TRANSIENT}.
   * @param loa the level of assurance of the eIDAS-Request. Can be null. The defaul value is
   *          {@link EidasLoaEnum#LOA_HIGH}.
   * @param issuer the issuer of the eIDAS-Request.
   * @param providerName the provider name of the eIDAS-Request. Can be null.
   * @param requesterId the requester id of the eIDAS-Request. Can be null.
   * @param signer the signer to sign the eIDAS-Request. Can be null, this would create unsigned requests.
   * @param testCase the enum of the test case for the eIDAS-Request. Can be null.
   * @see EidasRequest#EidasRequest(String, String, SPTypeEnumeration, EidasNameIdType, EidasLoaEnum, String, String,
   *      String, EidasSigner, TestCaseEnum) to create an eIDAS-Request with an id.
   */
  EidasRequest(String destination,
               SPTypeEnumeration sectorType,
               EidasNameIdType nameIdPolicy,
               EidasLoaEnum loa,
               String issuer,
               String providerName,
               String requesterId,
               EidasSigner signer,
               TestCaseEnum testCase)
  {
    this("_" + Utils.generateUniqueID(), destination, sectorType, nameIdPolicy, loa, issuer, providerName, requesterId,
         signer, testCase);
  }

  EidasRequest(String id,
               String destination,
               SPTypeEnumeration sectorType,
               EidasNameIdType nameIdPolicy,
               EidasLoaEnum loa,
               String issuer,
               String providerName,
               String requesterId,
               EidasSigner signer)
  {
    this(id, destination, sectorType, nameIdPolicy, loa, issuer, providerName, requesterId, signer, null);
  }

  /**
   * Creates an EidasRequest with an id and a test case.
   *
   * @param id the id of the eIDAS-Request.
   * @param destination the destination of the eIDAS-Request.
   * @param sectorType the sector type of the eIDAS-Request.
   * @param nameIdPolicy the nameIdPolicy of theeIDAS-Request. Can be null. The default value is
   *          {@link EidasNameIdType#TRANSIENT}.
   * @param loa the level of assurance of the eIDAS-Request. Can be null. The default value is
   *          {@link EidasLoaEnum#LOA_HIGH}.
   * @param issuer the issuer of the eIDAS-Request.
   * @param providerName the provider name of the eIDAS-Request. Can be null.
   * @param requesterId the requester id of the eIDAS-Request. Can be null.
   * @param signer the signer to sign the eIDAS-Request. Can be null, this would create unsigned requests.
   * @param testCase the enum of the test case for the eIDAS-Request. Can be null.
   * @see EidasRequest#EidasRequest(String, SPTypeEnumeration, EidasNameIdType, EidasLoaEnum, String, String, String,
   *      EidasSigner, TestCaseEnum) create an eIDAS-Request without an id.
   */
  EidasRequest(String id,
               String destination,
               SPTypeEnumeration sectorType,
               EidasNameIdType nameIdPolicy,
               EidasLoaEnum loa,
               String issuer,
               String providerName,
               String requesterId,
               EidasSigner signer,
               TestCaseEnum testCase)
  {
    this.id = id;
    this.destination = destination;
    this.issuer = issuer;
    this.providerName = providerName;
    this.requesterId = requesterId;
    this.signer = signer;
    this.sectorType = sectorType;
    this.nameIdPolicy = nameIdPolicy;
    this.authClassRef = loa;
    issueInstant = Instant.now();
    this.forceAuthn = true;
    this.isPassive = false;
    this.testCase = testCase;
  }

  byte[] generate(Map<EidasPersonAttributes, Boolean> requestedAttributes) throws CertificateEncodingException,
    MarshallingException, SignatureException, TransformerFactoryConfigurationError, TransformerException, IOException
  {
    authnRequest = new AuthnRequestBuilder().buildObject();
    authnRequest.getNamespaceManager()
                .registerNamespaceDeclaration(new Namespace(EidasConstants.EIDAS_NS, EidasConstants.EIDAS_PREFIX));
    authnRequest.setDestination(destination);
    authnRequest.setID(id);
    authnRequest.setIssueInstant(issueInstant);
    authnRequest.setForceAuthn(forceAuthn);
    authnRequest.setIsPassive(isPassive);
    authnRequest.setProviderName(providerName);

    Issuer iss = new IssuerBuilder().buildObject();
    iss.setFormat(NameIDType.ENTITY);
    iss.setValue(issuer);
    authnRequest.setIssuer(iss);

    if (requesterId != null)
    {
      Scoping scoping = new ScopingBuilder().buildObject();
      RequesterID requesterID = new RequesterIDBuilder().buildObject();
      requesterID.setRequesterID(requesterId);
      scoping.getRequesterIDs().add(requesterID);
      authnRequest.setScoping(scoping);
    }

    if (nameIdPolicy != null)
    {
      NameIDPolicy nameIDPolicy = new NameIDPolicyBuilder().buildObject();
      nameIDPolicy.setFormat(nameIdPolicy.getValue());
      nameIDPolicy.setAllowCreate(true);
      authnRequest.setNameIDPolicy(nameIDPolicy);
    }

    RequestedAuthnContext requestedAuthnContext = new RequestedAuthnContextBuilder().buildObject();
    requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.MINIMUM);
    AuthnContextClassRef authnContextClassRef = new AuthnContextClassRefBuilder().buildObject();
    String loa = authClassRef.getUri();
    if (testCase != null && loa.startsWith(EidasLoaEnum.LOA_TEST.getUri()))
    {
      loa += "#" + testCase.getTestCase();
    }
    authnContextClassRef.setURI(loa);
    requestedAuthnContext.getAuthnContextClassRefs().add(authnContextClassRef);
    authnRequest.setRequestedAuthnContext(requestedAuthnContext);

    Extensions extensions = new ExtensionsBuilder().buildObject();

    if (sectorType != null)
    {
      SPType spType = new SPTypeBuilder().buildObject();
      spType.setType(sectorType);
      extensions.getUnknownXMLObjects().add(spType);
    }

    if (!requestedAttributes.isEmpty())
    {
      RequestedAttributes requestedAttributesElement = new RequestedAttributesBuilder().buildObject();
      for ( Map.Entry<EidasPersonAttributes, Boolean> entry : requestedAttributes.entrySet() )
      {
        RequestedAttribute reqAttr = new RequestedAttributeBuilder().buildObject();
        reqAttr.setName(entry.getKey().getName());
        reqAttr.setNameFormat(Attribute.URI_REFERENCE);
        reqAttr.setIsRequired(entry.getValue());
        requestedAttributesElement.getRequestedAttributes().add(reqAttr);
      }
      extensions.getUnknownXMLObjects().add(requestedAttributesElement);
    }
    authnRequest.setExtensions(extensions);

    Element all;
    if (signer != null)
    {
      List<Signature> sigs = new ArrayList<>();
      XMLSignatureHandler.addSignature(authnRequest,
                                       signer.getSigKey(),
                                       signer.getSigCert(),
                                       signer.getSigType(),
                                       signer.getSigDigestAlg());
      sigs.add(authnRequest.getSignature());
      AuthnRequestMarshaller arm = new AuthnRequestMarshaller();
      all = arm.marshall(authnRequest);
      Signer.signObjects(sigs);
    }
    else
    {
      AuthnRequestMarshaller arm = new AuthnRequestMarshaller();
      all = arm.marshall(authnRequest);
    }

    Transformer trans = Utils.getTransformer();
    trans.setOutputProperty(OutputKeys.ENCODING, StandardCharsets.UTF_8.name());
    try (ByteArrayOutputStream bout = new ByteArrayOutputStream())
    {
      trans.transform(new DOMSource(all), new StreamResult(bout));
      return bout.toByteArray();
    }
  }

  public Set<Entry<EidasPersonAttributes, Boolean>> getRequestedAttributesEntries()
  {
    return requestedAttributes.entrySet();
  }

  static EidasRequest parse(InputStream is)
    throws XMLParserException, UnmarshallingException, ErrorCodeException, ComponentInitializationException
  {
    return parse(is, null);
  }

  static EidasRequest parse(InputStream is, List<X509Certificate> authors)
    throws XMLParserException, UnmarshallingException, ErrorCodeException, ComponentInitializationException
  {
    EidasRequest eidasReq = new EidasRequest();
    BasicParserPool ppMgr = Utils.getBasicParserPool();
    Document inCommonMDDoc = ppMgr.parse(is);

    Element metadataRoot = inCommonMDDoc.getDocumentElement();
    UnmarshallerFactory unmarshallerFactory = XMLObjectProviderRegistrySupport.getUnmarshallerFactory();
    Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(metadataRoot);
    eidasReq.authnRequest = (AuthnRequest)unmarshaller.unmarshall(metadataRoot);

    if (authors != null)
    {
      checkSignature(eidasReq.authnRequest.getSignature(), authors);
    }

    eidasReq.setPassive(getIsPassiveFromAuthnRequest(eidasReq));
    eidasReq.setForceAuthn(getIsForceAuthnFromAuthnRequest(eidasReq));

    eidasReq.id = eidasReq.authnRequest.getID();
    eidasReq.authClassRef = getAuthnContextClassRefFromAuthnRequest(eidasReq);
    eidasReq.issuer = eidasReq.authnRequest.getIssuer().getDOM().getTextContent();
    eidasReq.nameIdPolicy = getNameIdPolicy(eidasReq);

    eidasReq.issueInstant = eidasReq.authnRequest.getIssueInstant();
    eidasReq.destination = eidasReq.authnRequest.getDestination();
    setRequesterIdOrProviderName(eidasReq);
    processAuthnRequestExtension(eidasReq);

    return eidasReq;
  }

  private static EidasNameIdType getNameIdPolicy(EidasRequest eidasReq) throws ErrorCodeException
  {
    NameIDPolicy nameIDPolicy = eidasReq.authnRequest.getNameIDPolicy();
    if (nameIDPolicy == null)
    {
      return null;
    }
    try
    {
      return EidasNameIdType.getValueOf(nameIDPolicy.getFormat());
    }
    catch (ErrorCodeException e)
    {
      throw new ErrorCodeWithResponseException(ErrorCode.INVALID_NAME_ID_TYPE, eidasReq.issuer, eidasReq.getId());
    }
  }

  private static void processAuthnRequestExtension(EidasRequest eidasReq)
  {
    for ( XMLObject extension : eidasReq.authnRequest.getExtensions().getOrderedChildren() )
    {
      if ("RequestedAttributes".equals(extension.getElementQName().getLocalPart()))
      {
        collectEidasPersonAttributes(eidasReq, extension);
      }
      else if ("SPType".equals(extension.getElementQName().getLocalPart()))
      {
        eidasReq.sectorType = SPTypeHelper.getSPTypeFromString(extension.getDOM().getTextContent());
      }
    }
  }

  private static void collectEidasPersonAttributes(EidasRequest eidasReq, XMLObject extension)
  {
    for ( XMLObject attribute : extension.getOrderedChildren() )
    {
      Element el = attribute.getDOM();
      EidasPersonAttributes eidasPersonAttributes = getEidasPersonAttributes(el);
      if (null != eidasPersonAttributes)
      {
        eidasReq.requestedAttributes.put(eidasPersonAttributes, Boolean.parseBoolean(el.getAttribute("isRequired")));
      }
    }
  }

  private static void setRequesterIdOrProviderName(EidasRequest eidasReq) throws ErrorCodeException
  {

    if (isRequesterIdPresent(eidasReq))
    {
      eidasReq.requesterId = eidasReq.authnRequest.getScoping().getRequesterIDs().get(0).getRequesterID();
    }
    if (isProviderNamePresent(eidasReq))
    {
      eidasReq.providerName = eidasReq.authnRequest.getProviderName();
    }
  }

  private static EidasLoaEnum getAuthnContextClassRefFromAuthnRequest(EidasRequest eidasReq) throws ErrorCodeException
  {
    // there should be one AuthnContextClassRef
    AuthnContextClassRef ref = eidasReq.authnRequest.getRequestedAuthnContext().getAuthnContextClassRefs().get(0);
    if (ref == null)
    {
      throw new ErrorCodeException(ErrorCode.ILLEGAL_REQUEST_SYNTAX, "No AuthnContextClassRef element.");
    }
    String loa = ref.getURI();
    if (loa.startsWith(EidasLoaEnum.LOA_TEST.getUri()))
    {
      eidasReq.testCase = loa.contains("#") ? TestCaseEnum.parse(loa.substring(loa.indexOf('#') + 1)) : null;
      return EidasLoaEnum.LOA_TEST;
    }
    // returns null when the loa is unknown
    return EidasLoaEnum.parse(loa);
  }

  private static boolean getIsForceAuthnFromAuthnRequest(EidasRequest eidasReq) throws ErrorCodeException
  {
    // forceAuthn MUST be true as per spec
    if (Boolean.TRUE.equals(eidasReq.authnRequest.isForceAuthn()))
    {
      return true;
    }
    throw new ErrorCodeException(ErrorCode.ILLEGAL_REQUEST_SYNTAX,
                                 "Unsupported ForceAuthn value:" + eidasReq.authnRequest.isForceAuthn());
  }

  private static boolean getIsPassiveFromAuthnRequest(EidasRequest eidasReq) throws ErrorCodeException
  {
    // isPassive SHOULD be false
    if (Boolean.FALSE.equals(eidasReq.authnRequest.isPassive()))
    {
      return false;
    }
    throw new ErrorCodeException(ErrorCode.ILLEGAL_REQUEST_SYNTAX,
                                 "Unsupported IsPassive value:" + eidasReq.authnRequest.isPassive());
  }

  private static boolean isRequesterIdPresent(EidasRequest eidasReq)
  {
    return eidasReq.authnRequest.getScoping() != null && eidasReq.authnRequest.getScoping().getRequesterIDs() != null
           && eidasReq.authnRequest.getScoping().getRequesterIDs().size() == 1;
  }

  private static boolean isProviderNamePresent(EidasRequest eidasReq)
  {
    return null != eidasReq.authnRequest.getProviderName() && !eidasReq.authnRequest.getProviderName().isEmpty();
  }

  /**
   * Returns {@link EidasPersonAttributes} enum from given {@link Element}. In case enum can not be found null is
   * returned; unknown attributes should be ignored.
   *
   * @param el
   * @return
   */
  private static EidasPersonAttributes getEidasPersonAttributes(Element el)
  {
    EidasPersonAttributes eidasPersonAttributes = null;
    try
    {
      eidasPersonAttributes = EidasNaturalPersonAttributes.getValueOf(el.getAttribute("Name"));
    }
    catch (ErrorCodeException e)
    {

      // nothing

    }
    return eidasPersonAttributes;
  }

  static void checkSignature(Signature sig, List<X509Certificate> trustedAnchorList) throws ErrorCodeException
  {
    if (sig == null)
    {
      throw new ErrorCodeException(ErrorCode.SIGNATURE_CHECK_FAILED);
    }

    XMLSignatureHandler.checkSignature(sig, trustedAnchorList.toArray(new X509Certificate[trustedAnchorList.size()]));
  }
}

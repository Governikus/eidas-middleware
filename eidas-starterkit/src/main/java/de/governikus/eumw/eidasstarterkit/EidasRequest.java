/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.eidasstarterkit;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
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

import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.core.xml.io.UnmarshallerFactory;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.impl.AuthnRequestMarshaller;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.Signer;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import de.governikus.eumw.eidascommon.ErrorCode;
import de.governikus.eumw.eidascommon.ErrorCodeException;
import de.governikus.eumw.eidascommon.Utils;
import de.governikus.eumw.eidasstarterkit.person_attributes.EidasPersonAttributes;
import de.governikus.eumw.eidasstarterkit.template.TemplateLoader;
import lombok.extern.slf4j.Slf4j;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;
import net.shibboleth.utilities.java.support.xml.XMLParserException;


/**
 * @author hohnholt
 */
@Slf4j
public class EidasRequest
{

  private static final String ATTRIBUTE_TEMPLATE = "<eidas:RequestedAttribute Name=\"$NAME\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:uri\" isRequired=\"$ISREQ\"/>";

  private String id;

  private String destination;

  private String issuer;

  private String issueInstant;

  private String providerName;

  private String requesterId;

  private boolean forceAuthn;

  private boolean isPassive;

  private EidasRequestSectorType sectorType;

  private EidasNameIdType nameIdPolicy = EidasNameIdType.TRANSIENT;

  private EidasLoA authClassRef = EidasLoA.HIGH;

  private EidasSigner signer = null;

  private AuthnRequest request = null;

  private final Map<EidasPersonAttributes, Boolean> requestedAttributes = new HashMap<>();

  private EidasRequest()
  {
    super();
  }

  EidasRequest(String destination, String issuer, String providerName, EidasSigner signer)
  {
    this(destination, EidasRequestSectorType.PUBLIC, EidasNameIdType.TRANSIENT, EidasLoA.HIGH, issuer,
         providerName, signer);
  }

  EidasRequest(String destination, String issuer, String providerName, EidasSigner signer, String id)
  {
    this(id, destination, EidasRequestSectorType.PUBLIC, EidasNameIdType.TRANSIENT, EidasLoA.HIGH, issuer,
         providerName, signer);
  }

  EidasRequest(String destination,
               EidasRequestSectorType sectorType,
               EidasNameIdType nameIdPolicy,
               EidasLoA loa,
               String issuer,
               String providerName,
               EidasSigner signer)
  {
    this("_" + Utils.generateUniqueID(), destination, sectorType, nameIdPolicy, loa, issuer, providerName,
         signer);
  }

  EidasRequest(String id,
               String destination,
               EidasRequestSectorType sectorType,
               EidasNameIdType nameIdPolicy,
               EidasLoA loa,
               String issuer,
               String providerName,
               EidasSigner signer)
  {
    this.id = id;
    this.destination = destination;
    this.issuer = issuer;
    this.providerName = providerName;
    this.signer = signer;
    this.sectorType = sectorType;
    this.nameIdPolicy = nameIdPolicy;
    this.authClassRef = loa;
    issueInstant = Constants.format(new Date());
    this.forceAuthn = true;
    this.isPassive = false;
  }

  byte[] generate(Map<EidasPersonAttributes, Boolean> requestedAttributes)
    throws IOException, XMLParserException, UnmarshallingException, CertificateEncodingException,
    MarshallingException, SignatureException, TransformerFactoryConfigurationError, TransformerException,
    ComponentInitializationException
  {
    byte[] returnvalue = null;
    StringBuilder attributesBuilder = new StringBuilder();
    for ( Map.Entry<EidasPersonAttributes, Boolean> entry : requestedAttributes.entrySet() )
    {
      attributesBuilder.append(ATTRIBUTE_TEMPLATE.replace("$NAME", entry.getKey().getValue())
                                                 .replace("$ISREQ", entry.getValue().toString()));
    }

    String template = TemplateLoader.getTemplateByName("auth");
    template = template.replace("$ForceAuthn", Boolean.toString(this.forceAuthn));
    template = template.replace("$IsPassive", Boolean.toString(this.isPassive));
    template = template.replace("$Destination", destination);
    template = template.replace("$Id", id);
    template = template.replace("$IssuerInstand", issueInstant);
    template = template.replace("$ProviderName", providerName);
    template = template.replace("$Issuer", issuer);
    template = template.replace("$requestAttributes", attributesBuilder.toString());
    template = template.replace("$NameIDPolicy", nameIdPolicy.value);
    template = template.replace("$AuthClassRef", authClassRef.value);

    if (sectorType == null)
    {
      template = template.replace("$SPType", "");
    }
    else
    {
      template = template.replace("$SPType", "<eidas:SPType>" + sectorType.value + "</eidas:SPType>");
    }

    BasicParserPool ppMgr = Utils.getBasicParserPool();
    List<Signature> sigs = new ArrayList<>();

    try (InputStream is = new ByteArrayInputStream(template.getBytes(StandardCharsets.UTF_8)))
    {
      Document inCommonMDDoc = ppMgr.parse(is);
      Element metadataRoot = inCommonMDDoc.getDocumentElement();
      UnmarshallerFactory unmarshallerFactory = XMLObjectProviderRegistrySupport.getUnmarshallerFactory();
      Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(metadataRoot);
      request = (AuthnRequest)unmarshaller.unmarshall(metadataRoot);

      XMLSignatureHandler.addSignature(request,
                                       signer.getSigKey(),
                                       signer.getSigCert(),
                                       signer.getSigType(),
                                       signer.getSigDigestAlg());
      sigs.add(request.getSignature());

      AuthnRequestMarshaller arm = new AuthnRequestMarshaller();
      Element all = arm.marshall(request);
      if (!sigs.isEmpty())
      {
        Signer.signObjects(sigs);
      }

      Transformer trans = Utils.getTransformer();
      trans.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
      try (ByteArrayOutputStream bout = new ByteArrayOutputStream())
      {
        trans.transform(new DOMSource(all), new StreamResult(bout));
        returnvalue = bout.toByteArray();
      }
    }
    return returnvalue;
  }

  public boolean isPassive()
  {
    return isPassive;
  }

  public void setPassive(boolean isPassive)
  {
    this.isPassive = isPassive;
  }

  public void setIsForceAuthn(boolean forceAuthn)
  {
    this.forceAuthn = forceAuthn;
  }

  public boolean isForceAuthn()
  {
    return this.forceAuthn;
  }

  public String getId()
  {
    return id;
  }

  public String getDestination()
  {
    return destination;
  }

  public String getIssuer()
  {
    return issuer;
  }

  public String getIssueInstant()
  {
    return issueInstant;
  }

  public Set<Entry<EidasPersonAttributes, Boolean>> getRequestedAttributes()
  {
    return requestedAttributes.entrySet();
  }

  public Map<EidasPersonAttributes, Boolean> getRequestedAttributesMap()
  {
    return requestedAttributes;
  }

  /**
   * running EidasRequest.generate or EidasRequest.Parse creates is object
   *
   * @return the opensaml authnrespuest object or null. if not null, this object provides all information u
   *         can get via opensaml
   */
  public AuthnRequest getAuthnRequest()
  {
    return request;
  }

  public EidasRequestSectorType getSectorType()
  {
    return sectorType;
  }

  public void setSectorType(EidasRequestSectorType sectorType)
  {
    this.sectorType = sectorType;
  }

  public EidasNameIdType getNameIdPolicy()
  {
    return nameIdPolicy;
  }

  public void setNameIdPolicy(EidasNameIdType nameIdPolicy)
  {
    this.nameIdPolicy = nameIdPolicy;
  }

  public String getProviderName()
  {
    return providerName;
  }

  public String getRequesterId()
  {
    return requesterId;
  }

  public void setProviderName(String providerName)
  {
    this.providerName = providerName;
  }

  public EidasLoA getLevelOfAssurance()
  {
    return authClassRef;
  }

  public void setLevelOfAssurance(EidasLoA levelOfAssurance)
  {
    this.authClassRef = levelOfAssurance;
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
    eidasReq.request = (AuthnRequest)unmarshaller.unmarshall(metadataRoot);

    if (authors != null)
    {
      checkSignature(eidasReq.request.getSignature(), authors);
    }

    eidasReq.setPassive(getIsPassiveFromAuthnRequest(eidasReq));
    eidasReq.setIsForceAuthn(getIsForceAuthnFromAuthnRequest(eidasReq));

    eidasReq.id = eidasReq.request.getID();
    eidasReq.authClassRef = getAuthnContextClassRefFromAuthnRequest(eidasReq);
    String namiIdformat = eidasReq.request.getNameIDPolicy().getFormat();
    eidasReq.nameIdPolicy = EidasNameIdType.getValueOf(namiIdformat);

    eidasReq.issueInstant = Constants.format(eidasReq.request.getIssueInstant().toDate());
    eidasReq.issuer = eidasReq.request.getIssuer().getDOM().getTextContent();
    eidasReq.destination = eidasReq.request.getDestination();
    setRequesterIdOrProviderName(eidasReq);
    processAuthnRequestExtension(eidasReq);

    return eidasReq;
  }

  private static void processAuthnRequestExtension(EidasRequest eidasReq) throws ErrorCodeException
  {
    for ( XMLObject extension : eidasReq.request.getExtensions().getOrderedChildren() )
    {
      if ("RequestedAttributes".equals(extension.getElementQName().getLocalPart()))
      {
        collectEidasPersonAttributes(eidasReq, extension);
      }
      else if ("SPType".equals(extension.getElementQName().getLocalPart()))
      {
        eidasReq.sectorType = EidasRequestSectorType.getValueOf(extension.getDOM().getTextContent());
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
        eidasReq.requestedAttributes.put(eidasPersonAttributes,
                                         Boolean.parseBoolean(el.getAttribute("isRequired")));
      }
    }
  }

  private static void setRequesterIdOrProviderName(EidasRequest eidasReq) throws ErrorCodeException
  {
    checkIfRequesterIdAndProviderNameArePresent(eidasReq);

    if (isRequesterIdPresent(eidasReq))
    {
      eidasReq.requesterId = eidasReq.request.getScoping().getRequesterIDs().get(0).getRequesterID();
    }
    else if (isProviderNamePresent(eidasReq))
    {
      eidasReq.providerName = eidasReq.request.getProviderName();
    }
    else
    {
      log.debug("No requesterId or providerName attribute are present.");
      throw new ErrorCodeException(ErrorCode.ILLEGAL_REQUEST_SYNTAX,
                                   "No requesterId or providerName attribute are present");
    }
  }

  private static void checkIfRequesterIdAndProviderNameArePresent(EidasRequest eidasReq)
    throws ErrorCodeException
  {
    if (isRequesterIdPresent(eidasReq) && isProviderNamePresent(eidasReq))
    {
      log.debug("Both requesterId and providerName attributes are present.");
      throw new ErrorCodeException(ErrorCode.ILLEGAL_REQUEST_SYNTAX,
                                   "Both requesterId and providerName attributes are present");
    }
  }

  private static EidasLoA getAuthnContextClassRefFromAuthnRequest(EidasRequest eidasReq)
    throws ErrorCodeException
  {
    // there should be one AuthnContextClassRef
    AuthnContextClassRef ref = eidasReq.request.getRequestedAuthnContext().getAuthnContextClassRefs().get(0);
    if (ref == null)
    {
      throw new ErrorCodeException(ErrorCode.ILLEGAL_REQUEST_SYNTAX, "No AuthnContextClassRef element.");
    }
    return EidasLoA.getValueOf(ref.getDOM().getTextContent());
  }

  private static boolean getIsForceAuthnFromAuthnRequest(EidasRequest eidasReq) throws ErrorCodeException
  {
    // forceAuthn MUST be true as per spec
    if (Boolean.TRUE.equals(eidasReq.request.isForceAuthn()))
    {
      return true;
    }
    throw new ErrorCodeException(ErrorCode.ILLEGAL_REQUEST_SYNTAX,
                                 "Unsupported ForceAuthn value:" + eidasReq.request.isForceAuthn());
  }

  private static boolean getIsPassiveFromAuthnRequest(EidasRequest eidasReq) throws ErrorCodeException
  {
    // isPassive SHOULD be false
    if (Boolean.FALSE.equals(eidasReq.request.isPassive()))
    {
      return false;
    }
    throw new ErrorCodeException(ErrorCode.ILLEGAL_REQUEST_SYNTAX,
                                 "Unsupported IsPassive value:" + eidasReq.request.isPassive());
  }

  private static boolean isRequesterIdPresent(EidasRequest eidasReq)
  {
    return eidasReq.request.getScoping() != null && eidasReq.request.getScoping().getRequesterIDs() != null
           && eidasReq.request.getScoping().getRequesterIDs().size() == 1;
  }

  private static boolean isProviderNamePresent(EidasRequest eidasReq)
  {
    return null != eidasReq.request.getProviderName() && !eidasReq.request.getProviderName().isEmpty();
  }

  /**
   * Returns {@link EidasPersonAttributes} enum from given {@link Element}. In case enum can not be found null
   * is returned; unknown attributes should be ignored.
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
      try
      {
        eidasPersonAttributes = EidasLegalPersonAttributes.getValueOf(el.getAttribute("Name"));
      }
      catch (ErrorCodeException e1)
      {
        // nothing
      }
    }
    return eidasPersonAttributes;
  }

  static void checkSignature(Signature sig, List<X509Certificate> trustedAnchorList) throws ErrorCodeException
  {
    if (sig == null)
    {
      throw new ErrorCodeException(ErrorCode.SIGNATURE_CHECK_FAILED);
    }

    XMLSignatureHandler.checkSignature(sig,
                                       trustedAnchorList.toArray(new X509Certificate[trustedAnchorList.size()]));


  }

}

/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
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
import javax.xml.transform.TransformerFactory;
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
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;
import net.shibboleth.utilities.java.support.xml.XMLParserException;


/**
 * @author hohnholt
 */
public class EidasRequest
{

  private static final String ATTRIBUTE_TEMPLATE = "<eidas:RequestedAttribute Name=\"$NAME\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:uri\" isRequired=\"$ISREQ\"/>";

  private String id;

  private String destination;

  private String issuer;

  private String issueInstant;

  private String providerName;

  private boolean forceAuthn;

  private boolean isPassive;

  private EidasRequestSectorType selectorType = EidasRequestSectorType.PUBLIC;

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
                      EidasRequestSectorType selectorType,
                      EidasNameIdType nameIdPolicy,
                      EidasLoA loa,
                      String issuer,
                      String providerName,
                      EidasSigner signer)
  {
    this("_" + Utils.generateUniqueID(), destination, selectorType, nameIdPolicy, loa, issuer, providerName,
         signer);
  }

  EidasRequest(String id,
                      String destination,
                      EidasRequestSectorType selectorType,
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
    this.selectorType = selectorType;
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

    if (null != selectorType)
    {
      template = template.replace("$SPType", "<eidas:SPType>" + selectorType.value + "</eidas:SPType>");
    }
    else
    {
      template = template.replace("$SPType", "");
    }

    BasicParserPool ppMgr = new BasicParserPool();
    ppMgr.setNamespaceAware(true);
    ppMgr.initialize();
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

      Transformer trans = TransformerFactory.newInstance().newTransformer();
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

  public void setIsForceAuthn(Boolean forceAuthn)
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

  public EidasRequestSectorType getSelectorType()
  {
    return selectorType;
  }

  public void setSelectorType(EidasRequestSectorType selectorType)
  {
    this.selectorType = selectorType;
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
    throws XMLParserException, UnmarshallingException,
    ErrorCodeException, ComponentInitializationException
  {
    return parse(is, null);
  }

  static EidasRequest parse(InputStream is, List<X509Certificate> authors)
    throws XMLParserException,
    UnmarshallingException, ErrorCodeException, ComponentInitializationException
  {
    EidasRequest eidasReq = new EidasRequest();
    BasicParserPool ppMgr = new BasicParserPool();
    ppMgr.setNamespaceAware(true);
    ppMgr.initialize();
    Document inCommonMDDoc = ppMgr.parse(is);

    Element metadataRoot = inCommonMDDoc.getDocumentElement();
    UnmarshallerFactory unmarshallerFactory = XMLObjectProviderRegistrySupport.getUnmarshallerFactory();
    Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(metadataRoot);
    eidasReq.request = (AuthnRequest)unmarshaller.unmarshall(metadataRoot);

    if (authors != null)
    {
      checkSignature(eidasReq.request.getSignature(), authors);
    }

    // isPassive SHOULD be false
    if (!eidasReq.request.isPassive())
    {
      eidasReq.setPassive(eidasReq.request.isPassive());
    }
    else
    {
      throw new ErrorCodeException(ErrorCode.ILLEGAL_REQUEST_SYNTAX,
                                   "Unsupported IsPassive value:" + eidasReq.request.isPassive());
    }

    // forceAuthn MUST be true as per spec
    if (eidasReq.request.isForceAuthn())
    {
      eidasReq.setIsForceAuthn(eidasReq.request.isForceAuthn());
    }
    else
    {
      throw new ErrorCodeException(ErrorCode.ILLEGAL_REQUEST_SYNTAX,
                                   "Unsupported ForceAuthn value:" + eidasReq.request.isForceAuthn());
    }

    eidasReq.id = eidasReq.request.getID();
    // there should be one AuthnContextClassRef
    AuthnContextClassRef ref = eidasReq.request.getRequestedAuthnContext().getAuthnContextClassRefs().get(0);
    if (null != ref)
    {
      eidasReq.authClassRef = EidasLoA.getValueOf(ref.getDOM().getTextContent());
    }
    else
    {
      throw new ErrorCodeException(ErrorCode.ILLEGAL_REQUEST_SYNTAX, "No AuthnContextClassRef element.");
    }
    String namiIdformat = eidasReq.request.getNameIDPolicy().getFormat();
    eidasReq.nameIdPolicy = EidasNameIdType.getValueOf(namiIdformat);

    eidasReq.issueInstant = Constants.format(eidasReq.request.getIssueInstant().toDate());
    eidasReq.issuer = eidasReq.request.getIssuer().getDOM().getTextContent();
    eidasReq.destination = eidasReq.request.getDestination();

    if (null != eidasReq.request.getProviderName() && !eidasReq.request.getProviderName().isEmpty())
    {
      eidasReq.providerName = eidasReq.request.getProviderName();
    }
    else
    {
      throw new ErrorCodeException(ErrorCode.ILLEGAL_REQUEST_SYNTAX, "No providerName attribute.");
    }

    eidasReq.selectorType = null;
    for ( XMLObject extension : eidasReq.request.getExtensions().getOrderedChildren() )
    {
      if ("RequestedAttributes".equals(extension.getElementQName().getLocalPart()))
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
      else if ("SPType".equals(extension.getElementQName().getLocalPart()))
      {
        eidasReq.selectorType = EidasRequestSectorType.getValueOf(extension.getDOM().getTextContent());
      }
    }

    return eidasReq;
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

  private static void checkSignature(Signature sig, List<X509Certificate> trustedAnchorList)
    throws ErrorCodeException
  {
    if (sig == null)
    {
      throw new ErrorCodeException(ErrorCode.SIGNATURE_CHECK_FAILED);
    }

    XMLSignatureHandler.checkSignature(sig,
                                       trustedAnchorList.toArray(new X509Certificate[trustedAnchorList.size()]));


  }

}

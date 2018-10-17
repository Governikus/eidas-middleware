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
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactoryConfigurationError;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.commons.codec.binary.Base64;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.core.xml.io.UnmarshallerFactory;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml.saml2.metadata.impl.EntityDescriptorMarshaller;
import org.opensaml.security.credential.UsageType;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.X509Data;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.Signer;
import org.w3c.dom.DOMException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import de.governikus.eumw.eidascommon.ErrorCodeException;
import de.governikus.eumw.eidascommon.Utils;
import de.governikus.eumw.eidasstarterkit.template.TemplateLoader;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;
import net.shibboleth.utilities.java.support.xml.XMLParserException;


/**
 * Use this class to build a eu connector metadata.xml
 * 
 * @author hohnholt
 */
public class EidasMetadataNode
{

  private String id;

  private String entityId;

  private Date validUntil;

  private X509Certificate sigCert;

  private X509Certificate encCert;

  private EidasOrganisation organisation;

  private EidasContactPerson technicalcontact;

  private EidasContactPerson supportcontact;

  private String postEndpoint;

  private EidasRequestSectorType spType = EidasRequestSectorType.PUBLIC;

  private List<EidasNameIdType> supportedNameIdTypes = new ArrayList<>();

  private EidasMetadataNode()
  {
    super();
  }

  EidasMetadataNode(String id,
                    String entityId,
                    Date validUntil,
                    X509Certificate sigCert,
                    X509Certificate encCert,
                    EidasOrganisation organisation,
                    EidasContactPerson technicalcontact,
                    EidasContactPerson supportContact,
                    String postEndpoint,
                    EidasRequestSectorType spType,
                    List<EidasNameIdType> supportedNameIdTypes)
  {
    super();
    this.id = id;
    this.entityId = entityId;
    this.validUntil = validUntil;
    this.sigCert = sigCert;
    this.encCert = encCert;
    this.organisation = organisation;
    this.technicalcontact = technicalcontact;
    this.supportcontact = supportContact;
    this.postEndpoint = postEndpoint;
    this.spType = spType;
    this.supportedNameIdTypes = supportedNameIdTypes;

    if (this.supportedNameIdTypes == null)
    {
      this.supportedNameIdTypes = new ArrayList<>();
    }

    if (this.supportedNameIdTypes.isEmpty())
    {
      this.supportedNameIdTypes.add(EidasNameIdType.UNSPECIFIED);
    }
  }

  public String getPostEndpoint()
  {
    return postEndpoint;
  }

  public void setPostEndpoint(String postEndpoint)
  {
    this.postEndpoint = postEndpoint;
  }

  public String getId()
  {
    return id;
  }

  public void setId(String id)
  {
    this.id = id;
  }

  public String getEntityId()
  {
    return entityId;
  }

  public void setEntityId(String entityId)
  {
    this.entityId = entityId;
  }

  public Date getValidUntil()
  {
    return validUntil;
  }

  public void setValidUntil(Date validUntil)
  {
    this.validUntil = validUntil;
  }

  public X509Certificate getSigCert()
  {
    return sigCert;
  }

  public void setSigCert(X509Certificate sigCert)
  {
    this.sigCert = sigCert;
  }

  public X509Certificate getEncCert()
  {
    return encCert;
  }

  public void setEncCert(X509Certificate encCert)
  {
    this.encCert = encCert;
  }

  public EidasOrganisation getOrganisation()
  {
    return organisation;
  }

  public void setOrganisation(EidasOrganisation organisation)
  {
    this.organisation = organisation;
  }

  public EidasContactPerson getTechnicalcontact()
  {
    return technicalcontact;
  }

  public void setTechnicalcontact(EidasContactPerson technicalcontact)
  {
    this.technicalcontact = technicalcontact;
  }

  public EidasContactPerson getSupportcontact()
  {
    return supportcontact;
  }

  public void setSupportcontact(EidasContactPerson supportcontact)
  {
    this.supportcontact = supportcontact;
  }

  public EidasRequestSectorType getSpType()
  {
    return spType;
  }

  public void setSpType(EidasRequestSectorType spType)
  {
    this.spType = spType;
  }

  /**
   * Creates a metadata.xml as byte array
   * 
   * @param signer
   * @return metadata.xml byte array
   * @throws CertificateEncodingException
   * @throws IOException
   * @throws XMLParserException
   * @throws UnmarshallingException
   * @throws MarshallingException
   * @throws SignatureException
   * @throws TransformerFactoryConfigurationError
   * @throws TransformerException
   * @throws ComponentInitializationException
   */
  byte[] generate(EidasSigner signer) throws CertificateEncodingException, IOException, XMLParserException,
    UnmarshallingException, MarshallingException, SignatureException, TransformerFactoryConfigurationError,
    TransformerException, ComponentInitializationException
  {
    byte[] result = null;
    String template = TemplateLoader.getTemplateByName("metadatanode");
    template = template.replace("$Id", id);
    template = template.replace("$entityID", entityId);
    template = template.replace("$validUntil", Constants.format(validUntil));
    template = template.replace("$signCert",
                                new String(Base64.encodeBase64(sigCert.getEncoded(), false),
                                           StandardCharsets.UTF_8));
    template = template.replace("$encCert",
                                new String(Base64.encodeBase64(encCert.getEncoded(), false),
                                           StandardCharsets.UTF_8));
    template = template.replace("$landID", this.organisation.getLangId());

    template = template.replace("$orgName", organisation.getName());
    template = template.replace("$orgDisplayName", organisation.getDisplayName());
    template = template.replace("$orgUrl", organisation.getUrl());
    template = template.replace("$techPersonCompany", technicalcontact.getCompany());
    template = template.replace("$techPersonGivenName", technicalcontact.getGivenName());
    template = template.replace("$techPersonSurName", technicalcontact.getSurName());
    template = template.replace("$techPersonAddress", technicalcontact.getEmail());
    template = template.replace("$techPersonTel", supportcontact.getTel());
    template = template.replace("$supPersonCompany", supportcontact.getCompany());
    template = template.replace("$supPersonGivenName", supportcontact.getGivenName());
    template = template.replace("$supPersonSurName", supportcontact.getSurName());
    template = template.replace("$supPersonAddress", supportcontact.getEmail());
    template = template.replace("$supPersonTel", supportcontact.getTel());
    template = template.replace("$POST_ENDPOINT", postEndpoint);
    template = template.replace("$SPType", spType.value);



    StringBuilder sbSupportNameIDTypes = new StringBuilder();
    for ( EidasNameIdType nameIDType : this.supportedNameIdTypes )
    {
      sbSupportNameIDTypes.append("<md:NameIDFormat>" + nameIDType.value + "</md:NameIDFormat>");
    }
    template = template.replace("$SUPPORTED_NAMEIDTYPES", sbSupportNameIDTypes.toString());

    List<Signature> sigs = new ArrayList<>();
    BasicParserPool ppMgr = Utils.getBasicParserPool();
    try (InputStream is = new ByteArrayInputStream(template.getBytes(StandardCharsets.UTF_8)))
    {
      Document inCommonMDDoc = ppMgr.parse(is);
      Element metadataRoot = inCommonMDDoc.getDocumentElement();
      UnmarshallerFactory unmarshallerFactory = XMLObjectProviderRegistrySupport.getUnmarshallerFactory();
      Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(metadataRoot);
      EntityDescriptor metaData = (EntityDescriptor)unmarshaller.unmarshall(metadataRoot);

      XMLSignatureHandler.addSignature(metaData,
                                       signer.getSigKey(),
                                       signer.getSigCert(),
                                       signer.getSigType(),
                                       signer.getSigDigestAlg());
      sigs.add(metaData.getSignature());

      EntityDescriptorMarshaller arm = new EntityDescriptorMarshaller();
      Element all = arm.marshall(metaData);
      if (!sigs.isEmpty())
      {
        Signer.signObjects(sigs);
      }

      Transformer trans = Utils.getTransformer();
      trans.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
      try (ByteArrayOutputStream bout = new ByteArrayOutputStream())
      {
        trans.transform(new DOMSource(all), new StreamResult(bout));
        result = bout.toByteArray();
      }
    }
    return result;
  }

  /**
   * Parse an metadata.xml
   * 
   * @param is
   * @return
   * @throws XMLParserException
   * @throws UnmarshallingException
   * @throws CertificateException
   * @throws IOException
   * @throws ErrorCodeException
   * @throws DOMException
   * @throws ComponentInitializationException
   */
  static EidasMetadataNode parse(InputStream is, X509Certificate signer) throws XMLParserException,
    UnmarshallingException, CertificateException, ErrorCodeException, ComponentInitializationException
  {
    EidasMetadataNode eidasMetadataService = new EidasMetadataNode();
    BasicParserPool ppMgr = Utils.getBasicParserPool();
    Document inCommonMDDoc = ppMgr.parse(is);
    Element metadataRoot = inCommonMDDoc.getDocumentElement();
    UnmarshallerFactory unmarshallerFactory = XMLObjectProviderRegistrySupport.getUnmarshallerFactory();
    Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(metadataRoot);
    EntityDescriptor metaData = (EntityDescriptor)unmarshaller.unmarshall(metadataRoot);

    Signature sig = metaData.getSignature();
    if (sig != null)
    {
      XMLSignatureHandler.checkSignature(sig, signer);
    }

    eidasMetadataService.setId(metaData.getID());
    eidasMetadataService.setEntityId(metaData.getEntityID());
    eidasMetadataService.setValidUntil(metaData.getValidUntil() == null ? null
      : metaData.getValidUntil().toDate());
    if (metaData.getExtensions() != null)
    {
      Element extension = metaData.getExtensions().getDOM();
      for ( int i = 0 ; i < extension.getChildNodes().getLength() ; i++ )
      {
        Node n = extension.getChildNodes().item(i);
        if ("SPType".equals(n.getLocalName()))
        {
          eidasMetadataService.spType = EidasRequestSectorType.getValueOf(n.getTextContent());
          break;
        }
      }
    }

    SPSSODescriptor ssoDescriptor = metaData.getSPSSODescriptor("urn:oasis:names:tc:SAML:2.0:protocol");

    ssoDescriptor.getAssertionConsumerServices().forEach(s -> {
      String bindString = s.getBinding();
      if ("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST".equals(bindString))
      {
        eidasMetadataService.setPostEndpoint(s.getLocation());
      }
    });

    for ( KeyDescriptor k : ssoDescriptor.getKeyDescriptors() )
    {
      if (k.getUse() == UsageType.ENCRYPTION)
      {
        eidasMetadataService.encCert = getFirstCertFromKeyDescriptor(k);
      }
      else if (k.getUse() == UsageType.SIGNING)
      {
        eidasMetadataService.sigCert = getFirstCertFromKeyDescriptor(k);
      }
    }
    return eidasMetadataService;
  }

  /**
   * Search in a KeyDescriptor node for the frist certificate
   * 
   * @param keyDescriptor
   * @return the first Cert from the given keyDescriptor
   * @throws CertificateException
   */
  private static X509Certificate getFirstCertFromKeyDescriptor(KeyDescriptor keyDescriptor)
    throws CertificateException
  {
    java.security.cert.X509Certificate cert = null;
    if (keyDescriptor.getKeyInfo().getX509Datas() != null
        && !keyDescriptor.getKeyInfo().getX509Datas().isEmpty())
    {
      X509Data x509Data = keyDescriptor.getKeyInfo().getX509Datas().get(0);
      if (x509Data != null)
      {
        NodeList childs = x509Data.getDOM().getChildNodes();
        for ( int i = 0 ; i < childs.getLength() ; i++ )
        {
          if ("X509Certificate".equals(childs.item(i).getLocalName()))
          {
            String base64String = childs.item(i).getTextContent();
            byte[] bytes = Base64.decodeBase64(base64String);
            cert = Utils.readCert(bytes, true);
          }
        }
      }
    }
    return cert;
  }
}

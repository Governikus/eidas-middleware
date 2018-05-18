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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;

import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.TransformerFactoryConfigurationError;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.xml.security.algorithms.MessageDigestAlgorithm;
import org.apache.xml.security.signature.XMLSignature;
import org.joda.time.DateTime;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.core.xml.io.UnmarshallerFactory;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.core.xml.schema.XSAny;
import org.opensaml.core.xml.schema.impl.XSAnyBuilder;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.ext.saml2alg.DigestMethod;
import org.opensaml.saml.ext.saml2alg.SigningMethod;
import org.opensaml.saml.ext.saml2alg.impl.DigestMethodBuilder;
import org.opensaml.saml.ext.saml2alg.impl.SigningMethodBuilder;
import org.opensaml.saml.ext.saml2mdattr.EntityAttributes;
import org.opensaml.saml.ext.saml2mdattr.impl.EntityAttributesBuilder;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeValue;
import org.opensaml.saml.saml2.core.impl.AttributeBuilder;
import org.opensaml.saml.saml2.metadata.Company;
import org.opensaml.saml.saml2.metadata.ContactPerson;
import org.opensaml.saml.saml2.metadata.ContactPersonTypeEnumeration;
import org.opensaml.saml.saml2.metadata.EmailAddress;
import org.opensaml.saml.saml2.metadata.EncryptionMethod;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.Extensions;
import org.opensaml.saml.saml2.metadata.GivenName;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.saml2.metadata.NameIDFormat;
import org.opensaml.saml.saml2.metadata.Organization;
import org.opensaml.saml.saml2.metadata.OrganizationDisplayName;
import org.opensaml.saml.saml2.metadata.OrganizationName;
import org.opensaml.saml.saml2.metadata.OrganizationURL;
import org.opensaml.saml.saml2.metadata.SingleSignOnService;
import org.opensaml.saml.saml2.metadata.SurName;
import org.opensaml.saml.saml2.metadata.TelephoneNumber;
import org.opensaml.saml.saml2.metadata.impl.CompanyBuilder;
import org.opensaml.saml.saml2.metadata.impl.ContactPersonBuilder;
import org.opensaml.saml.saml2.metadata.impl.EmailAddressBuilder;
import org.opensaml.saml.saml2.metadata.impl.EncryptionMethodBuilder;
import org.opensaml.saml.saml2.metadata.impl.EntityDescriptorBuilder;
import org.opensaml.saml.saml2.metadata.impl.EntityDescriptorMarshaller;
import org.opensaml.saml.saml2.metadata.impl.ExtensionsBuilder;
import org.opensaml.saml.saml2.metadata.impl.GivenNameBuilder;
import org.opensaml.saml.saml2.metadata.impl.IDPSSODescriptorBuilder;
import org.opensaml.saml.saml2.metadata.impl.KeyDescriptorBuilder;
import org.opensaml.saml.saml2.metadata.impl.NameIDFormatBuilder;
import org.opensaml.saml.saml2.metadata.impl.OrganizationBuilder;
import org.opensaml.saml.saml2.metadata.impl.OrganizationDisplayNameBuilder;
import org.opensaml.saml.saml2.metadata.impl.OrganizationNameBuilder;
import org.opensaml.saml.saml2.metadata.impl.OrganizationURLBuilder;
import org.opensaml.saml.saml2.metadata.impl.SingleSignOnServiceBuilder;
import org.opensaml.saml.saml2.metadata.impl.SurNameBuilder;
import org.opensaml.saml.saml2.metadata.impl.TelephoneNumberBuilder;
import org.opensaml.security.credential.UsageType;
import org.opensaml.xmlsec.encryption.support.EncryptionConstants;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.X509Data;
import org.opensaml.xmlsec.signature.impl.KeyInfoBuilder;
import org.opensaml.xmlsec.signature.impl.X509CertificateBuilder;
import org.opensaml.xmlsec.signature.impl.X509DataBuilder;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.Signer;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import de.governikus.eumw.eidascommon.Utils;
import de.governikus.eumw.eidasstarterkit.person_attributes.EidasPersonAttributes;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;
import net.shibboleth.utilities.java.support.xml.XMLParserException;


/**
 * Use this class to build a service provider metadata.xml
 * 
 * @author hohnholt
 */
class EidasMetadataService
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

  private String redirectEndpoint;

  private List<EidasPersonAttributes> attributes = new ArrayList<>();

  private List<EidasNameIdType> supportedNameIdTypes = new ArrayList<>();

  private EidasMetadataService()
  {
    super();
  }

  EidasMetadataService(String id,
                              String entityId,
                              Date validUntil,
                              X509Certificate sigCert,
                              X509Certificate encCert,
                              EidasOrganisation organisation,
                              EidasContactPerson technicalContact,
                              EidasContactPerson supportContact,
                              String postEndpoint,
                              String redirectEndpoint,
                              List<EidasNameIdType> supportedNameIdTypes)
  {
    super();
    this.id = id;
    this.entityId = entityId;
    this.validUntil = validUntil;
    this.sigCert = sigCert;
    this.encCert = encCert;
    this.organisation = organisation;
    this.technicalcontact = technicalContact;
    this.supportcontact = supportContact;
    this.postEndpoint = postEndpoint;
    this.redirectEndpoint = redirectEndpoint;
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

  public String getRedirectEndpoint()
  {
    return redirectEndpoint;
  }

  public void setRedirectEndpoint(String redirectEndpoint)
  {
    this.redirectEndpoint = redirectEndpoint;
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

  public EidasContactPerson getTechnicalContact()
  {
    return technicalcontact;
  }

  public void setTechnicalContact(EidasContactPerson contact)
  {
    this.technicalcontact = contact;
  }

  public EidasContactPerson getSupportcontact()
  {
    return supportcontact;
  }

  public void setSupportcontact(EidasContactPerson supportcontact)
  {
    this.supportcontact = supportcontact;
  }

  public List<EidasPersonAttributes> getAttributes()
  {
    return attributes;
  }

  public void setAttributes(List<EidasPersonAttributes> attributes)
  {
    this.attributes = attributes;
  }

  byte[] generate(List<EidasPersonAttributes> attributes, EidasSigner signer)
    throws CertificateEncodingException, IOException, MarshallingException, SignatureException,
    TransformerFactoryConfigurationError, TransformerException
  {
    EntityDescriptor entityDescriptor = new EntityDescriptorBuilder().buildObject();
    entityDescriptor.setID(id);
    entityDescriptor.setEntityID(entityId);
    entityDescriptor.setValidUntil(new DateTime(validUntil.getTime()));

    IDPSSODescriptor idpDescriptor = new IDPSSODescriptorBuilder().buildObject();
    idpDescriptor.setWantAuthnRequestsSigned(true);
    idpDescriptor.addSupportedProtocol(SAMLConstants.SAML20P_NS);

    KeyDescriptor kd = new KeyDescriptorBuilder().buildObject();
    kd.setUse(UsageType.SIGNING);
    KeyInfo ki = new KeyInfoBuilder().buildObject();
    X509Data x509 = new X509DataBuilder().buildObject();
    org.opensaml.xmlsec.signature.X509Certificate x509Cert = new X509CertificateBuilder().buildObject();
    x509Cert.setValue(new String(Base64.getEncoder().encode(sigCert.getEncoded()), StandardCharsets.UTF_8));
    x509.getX509Certificates().add(x509Cert);
    ki.getX509Datas().add(x509);
    kd.setKeyInfo(ki);
    idpDescriptor.getKeyDescriptors().add(kd);

    kd = new KeyDescriptorBuilder().buildObject();
    kd.setUse(UsageType.ENCRYPTION);
    ki = new KeyInfoBuilder().buildObject();
    x509 = new X509DataBuilder().buildObject();
    x509Cert = new X509CertificateBuilder().buildObject();
    x509Cert.setValue(new String(Base64.getEncoder().encode(sigCert.getEncoded()), StandardCharsets.UTF_8));
    x509.getX509Certificates().add(x509Cert);
    ki.getX509Datas().add(x509);
    kd.setKeyInfo(ki);
    EncryptionMethod encMethod = new EncryptionMethodBuilder().buildObject();
    encMethod.setAlgorithm(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES256_GCM);
    kd.getEncryptionMethods().add(encMethod);
    idpDescriptor.getKeyDescriptors().add(kd);

    SingleSignOnService sso = new SingleSignOnServiceBuilder().buildObject();
    sso.setBinding(SAMLConstants.SAML2_POST_BINDING_URI);
    sso.setLocation(postEndpoint);
    idpDescriptor.getSingleSignOnServices().add(sso);

    sso = new SingleSignOnServiceBuilder().buildObject();
    sso.setBinding(SAMLConstants.SAML2_REDIRECT_BINDING_URI);
    sso.setLocation(redirectEndpoint);
    idpDescriptor.getSingleSignOnServices().add(sso);

    for ( EidasNameIdType nameIDType : this.supportedNameIdTypes )
    {
      NameIDFormat nif = new NameIDFormatBuilder().buildObject();
      nif.setFormat(nameIDType.value);
      idpDescriptor.getNameIDFormats().add(nif);
    }

    for ( EidasPersonAttributes att : attributes )
    {
      Attribute a = new AttributeBuilder().buildObject();
      a.setFriendlyName(att.getFriendlyName());
      a.setName(att.getValue());
      idpDescriptor.getAttributes().add(a);
    }

    entityDescriptor.getRoleDescriptors().add(idpDescriptor);

    Organization organization = new OrganizationBuilder().buildObject();
    OrganizationDisplayName odn = new OrganizationDisplayNameBuilder().buildObject();
    odn.setValue(organisation.getDisplayName());
    odn.setXMLLang(organisation.getLangId());
    organization.getDisplayNames().add(odn);
    OrganizationName on = new OrganizationNameBuilder().buildObject();
    on.setValue(organisation.getName());
    on.setXMLLang(organisation.getLangId());
    organization.getOrganizationNames().add(on);
    OrganizationURL ourl = new OrganizationURLBuilder().buildObject();
    ourl.setValue(organisation.getUrl());
    ourl.setXMLLang(organisation.getLangId());
    organization.getURLs().add(ourl);
    entityDescriptor.setOrganization(organization);

    ContactPerson cp = new ContactPersonBuilder().buildObject();
    Company comp = new CompanyBuilder().buildObject();
    comp.setName(technicalcontact.getCompany());
    cp.setCompany(comp);
    GivenName gn = new GivenNameBuilder().buildObject();
    gn.setName(technicalcontact.getGivenName());
    cp.setGivenName(gn);
    SurName sn = new SurNameBuilder().buildObject();
    sn.setName(technicalcontact.getSurName());
    cp.setSurName(sn);
    EmailAddress email = new EmailAddressBuilder().buildObject();
    email.setAddress(technicalcontact.getEmail());
    cp.getEmailAddresses().add(email);
    TelephoneNumber tel = new TelephoneNumberBuilder().buildObject();
    tel.setNumber(technicalcontact.getTel());
    cp.getTelephoneNumbers().add(tel);
    cp.setType(ContactPersonTypeEnumeration.TECHNICAL);
    entityDescriptor.getContactPersons().add(cp);

    cp = new ContactPersonBuilder().buildObject();
    comp = new CompanyBuilder().buildObject();
    comp.setName(supportcontact.getCompany());
    cp.setCompany(comp);
    gn = new GivenNameBuilder().buildObject();
    gn.setName(supportcontact.getGivenName());
    cp.setGivenName(gn);
    sn = new SurNameBuilder().buildObject();
    sn.setName(supportcontact.getSurName());
    cp.setSurName(sn);
    email = new EmailAddressBuilder().buildObject();
    email.setAddress(supportcontact.getEmail());
    cp.getEmailAddresses().add(email);
    tel = new TelephoneNumberBuilder().buildObject();
    tel.setNumber(supportcontact.getTel());
    cp.getTelephoneNumbers().add(tel);
    cp.setType(ContactPersonTypeEnumeration.SUPPORT);
    entityDescriptor.getContactPersons().add(cp);

    EntityAttributes entAttr = new EntityAttributesBuilder().buildObject();
    Attribute attr = new AttributeBuilder().buildObject();
    attr.setName("urn:oasis:names:tc:SAML:attribute:assurance-certification");
    attr.setNameFormat(Attribute.URI_REFERENCE);
    XSAny any = new XSAnyBuilder().buildObject(AttributeValue.DEFAULT_ELEMENT_NAME);
    any.setTextContent("http://eidas.europa.eu/LoA/high");
    attr.getAttributeValues().add(any);
    entAttr.getAttributes().add(attr);
    Extensions ext = new ExtensionsBuilder().buildObject();
    ext.getUnknownXMLObjects().add(entAttr);

    DigestMethod dm = new DigestMethodBuilder().buildObject();
    dm.setAlgorithm(MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA256);
    ext.getUnknownXMLObjects().add(dm);

    SigningMethod sm = new SigningMethodBuilder().buildObject();
    sm.setAlgorithm(XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256);
    sm.setMinKeySize(256);
    ext.getUnknownXMLObjects().add(sm);

    sm = new SigningMethodBuilder().buildObject();
    sm.setAlgorithm(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256);
    sm.setMinKeySize(3072);
    sm.setMaxKeySize(4096);
    ext.getUnknownXMLObjects().add(sm);

    entityDescriptor.setExtensions(ext);

    byte[] result = null;
    List<Signature> sigs = new ArrayList<>();

    XMLSignatureHandler.addSignature(entityDescriptor,
                                     signer.getSigKey(),
                                     signer.getSigCert(),
                                     signer.getSigType(),
                                     signer.getSigDigestAlg());
    sigs.add(entityDescriptor.getSignature());

    EntityDescriptorMarshaller arm = new EntityDescriptorMarshaller();
    Element all = arm.marshall(entityDescriptor);
    if (!sigs.isEmpty())
    {
      Signer.signObjects(sigs);
    }

    Transformer trans = TransformerFactory.newInstance().newTransformer();
    trans.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
    try (ByteArrayOutputStream bout = new ByteArrayOutputStream())
    {
      trans.transform(new DOMSource(all), new StreamResult(bout));
      result = bout.toByteArray();
    }
    return result;
  }

  static EidasMetadataService parse(InputStream is)
    throws XMLParserException, UnmarshallingException,
    CertificateException, ComponentInitializationException
  {
    EidasMetadataService eidasMetadataService = new EidasMetadataService();
    BasicParserPool ppMgr = new BasicParserPool();
    ppMgr.initialize();
    Document inCommonMDDoc = ppMgr.parse(is);
    Element metadataRoot = inCommonMDDoc.getDocumentElement();
    UnmarshallerFactory unmarshallerFactory = XMLObjectProviderRegistrySupport.getUnmarshallerFactory();
    Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(metadataRoot);
    EntityDescriptor metaData = (EntityDescriptor)unmarshaller.unmarshall(metadataRoot);
    eidasMetadataService.setSupportcontact(unmarshalContactPerson(metaData.getContactPersons(), "support"));
    eidasMetadataService.setTechnicalContact(unmarshalContactPerson(metaData.getContactPersons(),
                                                                    "technical"));
    eidasMetadataService.setOrganisation(unmarshalOrganisation(metaData.getOrganization()));
    eidasMetadataService.setId(metaData.getID());
    eidasMetadataService.setEntityId(metaData.getEntityID());
    eidasMetadataService.setValidUntil(metaData.getValidUntil().toDate());
    IDPSSODescriptor idpssoDescriptor = metaData.getIDPSSODescriptor("urn:oasis:names:tc:SAML:2.0:protocol");
    idpssoDescriptor.getSingleSignOnServices().forEach(s -> {
      String bindString = s.getBinding();
      if ("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST".equals(bindString))
      {
        eidasMetadataService.setPostEndpoint(s.getLocation());
      }
      else if ("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect".equals(bindString))
      {
        eidasMetadataService.setRedirectEndpoint(s.getLocation());
      }
    });
    List<EidasPersonAttributes> attributes = new ArrayList<>();
    idpssoDescriptor.getAttributes().forEach(a -> {
      EidasPersonAttributes eidasPersonAttributes = null;
      try
      {
        eidasPersonAttributes = EidasNaturalPersonAttributes.getValueOf(a.getName());
      }
      catch (Exception e1)
      { // legal person?
        try
        {
          eidasPersonAttributes = EidasLegalPersonAttributes.getValueOf(a.getName());
        }
        catch (Exception e)
        { // no natural and no legal
          // ignore error, perhaps log?
        }
      }

      attributes.add(eidasPersonAttributes);
    });
    eidasMetadataService.setAttributes(attributes);
    for ( KeyDescriptor k : idpssoDescriptor.getKeyDescriptors() )
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

  private static EidasContactPerson unmarshalContactPerson(List<ContactPerson> cps, String contactType)
  {
    for ( ContactPerson cp : cps )
    {
      String company = cp.getCompany().getName();
      String givenName = cp.getGivenName().getName();
      String surName = cp.getSurName().getName();
      String tel = cp.getTelephoneNumbers().get(0).getNumber();
      String email = cp.getEmailAddresses().get(0).getAddress();
      String type = cp.getType().toString();
      EidasContactPerson ecp = new EidasContactPerson(company, givenName, surName, tel, email, type);
      if (type != null && (type).equalsIgnoreCase(contactType))
      {
        return ecp;
      }
    }
    return null;
  }

  private static EidasOrganisation unmarshalOrganisation(Organization org)
  {
    String displayName = org.getDisplayNames().get(0).getValue();
    String name = org.getOrganizationNames().get(0).getValue();
    String url = org.getURLs().get(0).getValue();
    String langId = org.getDisplayNames().get(0).getXMLLang();
    return new EidasOrganisation(name, displayName, url, langId);
  }

  private static java.security.cert.X509Certificate getFirstCertFromKeyDescriptor(KeyDescriptor k)
    throws CertificateException
  {
    java.security.cert.X509Certificate x = null;
    if (k.getKeyInfo().getX509Datas() != null && !k.getKeyInfo().getX509Datas().isEmpty())
    {
      X509Data d = k.getKeyInfo().getX509Datas().get(0);
      if (d != null)
      {
        NodeList childs = d.getDOM().getChildNodes();
        for ( int i = 0 ; i < childs.getLength() ; i++ )
        {
          if ("X509Certificate".equals(childs.item(i).getLocalName()))
          {
            String base64String = childs.item(i).getTextContent();
            byte[] bytes = Base64.getDecoder().decode(base64String);
            x = Utils.readCert(bytes, true);
          }
        }
      }
    }
    return x;
  }
}

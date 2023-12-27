package de.governikus.eumw.eidasstarterkit.additional.attributes;

import javax.xml.namespace.QName;

import org.opensaml.core.xml.schema.XSString;

import se.swedenconnect.opensaml.eidas.common.EidasConstants;
import se.swedenconnect.opensaml.eidas.ext.attributes.EidasAttributeValueType;


/**
 * The eIDAS {@code NationalityType}.
 * 
 * <pre>
 * {@code 
 * <xsd:simpleType name="NationalityType">
 *   <xsd:annotation>
 *     <xsd:documentation>
 *       Nationality of the natural person (Two-letter country codes
 *       according to ISO 3166-1 standard).
 *     </xsd:documentation>
 *   </xsd:annotation>
 *   <xsd:restriction base="xsd:string">
 *     <xsd:pattern value="[A-Z][A-Z]"/>
 *   </xsd:restriction>
 * </xsd:simpleType>}
 * </pre>
 * 
 * Example:
 * 
 * <pre>
 * {@code
 * <saml:Attribute
 *   FriendlyName="Nationality"
 *   Name="http://eidas.europa.eu/attributes/naturalperson/Nationality"
 *   NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
 *   <saml:AttributeValue xsi:type="eidas:NationalityType">
 *     LU
 *   </saml:AttributeValue>
 * </saml:Attribute>}
 * </pre>
 */
public interface NationalityType extends XSString, EidasAttributeValueType
{

  /** Local name of the XSI type. */
  public static final String TYPE_LOCAL_NAME = "NationalityType";

  /** QName of the XSI type. */
  public static final QName TYPE_NAME = new QName(EidasConstants.EIDAS_NP_NS, TYPE_LOCAL_NAME,
                                                  EidasConstants.EIDAS_NP_PREFIX);
}

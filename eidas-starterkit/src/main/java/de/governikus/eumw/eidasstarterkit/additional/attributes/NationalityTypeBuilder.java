package de.governikus.eumw.eidasstarterkit.additional.attributes;

import org.opensaml.core.xml.AbstractXMLObjectBuilder;


/**
 * Builder for {@link NationalityType}.
 */
public class NationalityTypeBuilder extends AbstractXMLObjectBuilder<NationalityType>
{

  /** {@inheritDoc} */
  @Override
  public NationalityType buildObject(String namespaceURI, String localName, String namespacePrefix)
  {
    return new NationalityTypeImpl(namespaceURI, localName, namespacePrefix);
  }
}

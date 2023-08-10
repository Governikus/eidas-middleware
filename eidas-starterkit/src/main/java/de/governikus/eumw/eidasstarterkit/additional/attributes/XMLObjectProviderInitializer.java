package de.governikus.eumw.eidasstarterkit.additional.attributes;

import org.opensaml.core.xml.config.AbstractXMLObjectProviderInitializer;


/**
 * Initialize XML handling for additional attributes.
 */
public class XMLObjectProviderInitializer extends AbstractXMLObjectProviderInitializer
{

  /** {@inheritDoc} */
  @Override
  protected String[] getConfigResources()
  {
    return new String[]{"/additional-attribs-config.xml"};
  }
}

package de.governikus.eumw.eidasstarterkit.additional.attributes;

import org.opensaml.core.xml.schema.impl.XSStringImpl;


/**
 * Implementation class for {@link NationalityType}.
 */
public class NationalityTypeImpl extends XSStringImpl implements NationalityType
{

  /**
   * Constructor.
   * 
   * @param namespaceURI the namespace the element is in
   * @param elementLocalName the local name of the XML element this Object represents
   * @param namespacePrefix the prefix for the given namespace
   */
  public NationalityTypeImpl(String namespaceURI, String elementLocalName, String namespacePrefix)
  {
    super(namespaceURI, elementLocalName, namespacePrefix);
  }

  /** {@inheritDoc} */
  @Override
  public String toStringValue()
  {
    return getValue();
  }

  /** {@inheritDoc} */
  @Override
  public void parseStringValue(String value)
  {
    if (value != null && value.matches("[A-Z][A-Z]"))
    {
      setValue(value);
    }
  }
}

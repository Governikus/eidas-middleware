package de.governikus.eumw.eidasstarterkit.person_attributes.natural_persons_attribute;

import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeValue;

import de.governikus.eumw.eidasstarterkit.EidasNaturalPersonAttributes;
import de.governikus.eumw.eidasstarterkit.additional.attributes.NationalityType;
import de.governikus.eumw.eidasstarterkit.additional.attributes.NationalityTypeBuilder;
import de.governikus.eumw.eidasstarterkit.person_attributes.AbstractEidasAttribute;
import de.governikus.eumw.eidasstarterkit.person_attributes.EidasPersonAttributes;
import lombok.NoArgsConstructor;
import se.litsec.eidas.opensaml.ext.attributes.AttributeConstants;


/**
 * Attribute for nationality.
 */
@NoArgsConstructor
public class NationalityAttribute extends AbstractEidasAttribute
{

  public static final String NATIONALITY_ATTRIBUTE_FRIENDLY_NAME = "Nationality";

  public static final String NATIONALITY_ATTRIBUTE_NAME = AttributeConstants.NATURAL_PERSON_PREFIX
                                                          + NATIONALITY_ATTRIBUTE_FRIENDLY_NAME;

  /**
   * Constructor.
   * 
   * @param nationality
   */
  public NationalityAttribute(String nationality)
  {
    super(nationality);
  }

  /** {@inheritDoc} */
  @Override
  public EidasPersonAttributes type()
  {
    return EidasNaturalPersonAttributes.NATIONALITY;
  }

  /** {@inheritDoc} */
  @Override
  public Attribute generate()
  {
    Attribute attr = super.generate();
    NationalityType nationality = new NationalityTypeBuilder().buildObject(AttributeValue.DEFAULT_ELEMENT_NAME,
                                                                           type().getQName());
    nationality.setValue(getValue());
    attr.getAttributeValues().add(nationality);
    return attr;
  }
}

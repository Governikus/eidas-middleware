/*
 * Copyright (c) 2019 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.eidasstarterkit;

import de.governikus.eumw.eidasstarterkit.person_attributes.EidasPersonAttributes;


/**
 * @author hohnholt
 */
public interface EidasAttribute
{

  /**
   * @return An SAML XML attribute as String
   */
  public String generate();

  /**
   * @return the type as string. Compare it with the Type consts of this class
   */
  public EidasAttributeType type();

  /**
   * @return the type as EidasNaturalPersonAttributes enum
   */
  public EidasPersonAttributes getPersonAttributeType();

  /**
   * Set the attribute value
   */
  public void setLatinScript(String value);

  /**
   * Get a string-representation of the attribute value
   *
   * @return a String containing the attribute value
   */
  public String getLatinScript();


  enum EidasAttributeType
  {
    BIRTH_NAME("BirthNameAttribute"),
    CURRENT_ADDRESS("CurrentAddressAttribute"),
    DATE_OF_BIRTH("DateOfBirthAttribute"),
    FAMILY_NAME("FamilyNameAttribute"),
    GIVEN_NAME("GivenNameAttribute"),
    PERSON_ID("PersonIdentifierAttribute"),
    PLACE_OF_BIRTH("PlaceOfBirthAttribute"),
    /** Legal Attributes **/
    D_2012_17_EU_IDENTIFIER("D201217EUIdentifierAttribute"),
    EORI("EORIAttribute"),
    LEGAL_ENTITY_IDENTIFIER("LegalEntityIdentifierAttribute"),
    LEGAL_NAME("LegalNameAttribute"),
    LEGAL_PERSON_ADDRESS("LegalPersonAddressAttribute"),
    LEGAL_PERSON_IDENTIFIER("LegalPersonIdentifierAttribute"),
    SEED("SEEDAttribute"),
    SIC("SICAttribute"),
    TAX_REFERENCE("TaxReferenceAttribute"),
    VAT_REGISTRATION("VatRegistrationAttribute"),
    GENDER("GenderAttribute");

    public final String value;

    private EidasAttributeType(String value)
    {
      this.value = value;
    }

    @Override
    public String toString()
    {
      return value;
    }

  }
}

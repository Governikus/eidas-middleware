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

import de.governikus.eumw.eidascommon.ErrorCode;
import de.governikus.eumw.eidascommon.ErrorCodeException;
import de.governikus.eumw.eidasstarterkit.person_attributes.EidasPersonAttributes;
import de.governikus.eumw.eidasstarterkit.person_attributes.legal_persons_attributes.EORIAttribute;
import de.governikus.eumw.eidasstarterkit.person_attributes.legal_persons_attributes.EUIdentifierAttribute;
import de.governikus.eumw.eidasstarterkit.person_attributes.legal_persons_attributes.LegalAddressAttribute;
import de.governikus.eumw.eidasstarterkit.person_attributes.legal_persons_attributes.LegalEntityIdentifierAttribute;
import de.governikus.eumw.eidasstarterkit.person_attributes.legal_persons_attributes.LegalNameAttribute;
import de.governikus.eumw.eidasstarterkit.person_attributes.legal_persons_attributes.LegalPersonIdentifierAttribute;
import de.governikus.eumw.eidasstarterkit.person_attributes.legal_persons_attributes.SEEDAttribute;
import de.governikus.eumw.eidasstarterkit.person_attributes.legal_persons_attributes.SICAttribute;
import de.governikus.eumw.eidasstarterkit.person_attributes.legal_persons_attributes.TaxReferenceAttribute;
import de.governikus.eumw.eidasstarterkit.person_attributes.legal_persons_attributes.VATRegistrationAttribute;


public enum EidasLegalPersonAttributes implements EidasPersonAttributes
{

  LEGAL_PERSON_IDENTIFIER("http://eidas.europa.eu/attributes/legalperson/LegalPersonIdentifier",
                        "LegalPersonIdentifier",
                        LegalPersonIdentifierAttribute.class),
  LEGAL_NAME("http://eidas.europa.eu/attributes/legalperson/LegalName", "LegalName", LegalNameAttribute.class),
  LEGAL_ADDRESS("http://eidas.europa.eu/attributes/legalperson/LegalPersonAddress",
               "LegalAddress",
               LegalAddressAttribute.class),
  VAT_REGISTRATION("http://eidas.europa.eu/attributes/legalperson/VATRegistrationNumber",
                  "VATRegistration",
                  VATRegistrationAttribute.class),
  TAX_REFERENCE("http://eidas.europa.eu/attributes/legalperson/TaxReference",
               "TaxReference",
               TaxReferenceAttribute.class),
  D2012_17_EU_IDENTIFIER("http://eidas.europa.eu/attributes/legalperson/D-2012-17-EUIdentifier",
                        "D-2012-17-EUIdentifier",
                        EUIdentifierAttribute.class),
  LEI("http://eidas.europa.eu/attributes/legalperson/LEI", "LEI", LegalEntityIdentifierAttribute.class),
  EORI("http://eidas.europa.eu/attributes/legalperson/EORI", "EORI", EORIAttribute.class),
  SEED("http://eidas.europa.eu/attributes/legalperson/SEED", "SEED", SEEDAttribute.class),
  SIC("http://eidas.europa.eu/attributes/legalperson/SIC", "SIC", SICAttribute.class);

  public final String value;

  public final String friendlyName;

  public final Class<? extends EidasAttribute> attributeClass;

  EidasLegalPersonAttributes(String value, String friendlyName, Class<? extends EidasAttribute> attrClazz)
  {
    this.value = value;
    this.friendlyName = friendlyName;
    this.attributeClass = attrClazz;
  }

  static EidasLegalPersonAttributes getValueOf(String s) throws ErrorCodeException
  {
    for ( EidasLegalPersonAttributes elpa : EidasLegalPersonAttributes.values() )
    {
      if (elpa.value.equals(s))
      {
        return elpa;
      }
    }
    throw new ErrorCodeException(ErrorCode.ILLEGAL_REQUEST_SYNTAX, "Unsupported loa value:" + s);
  }

  /**
   * Create an instance of the EidasAttribute corresponding to the NaturalPersonAttribute type
   * 
   * @return instance of EidasAttribute corresponding to the NaturalPersonAttribute type
   */
  @Override
  public EidasAttribute getInstance()
  {
    try
    {
      return attributeClass.newInstance();
    }
    catch (InstantiationException | IllegalAccessException e)
    {
      throw new IllegalStateException("Unable to instantiate attribute type.", e);
    }
  }

  @Override
  public String getValue()
  {
    return value;
  }

  @Override
  public String getFriendlyName()
  {
    return friendlyName;
  }
}

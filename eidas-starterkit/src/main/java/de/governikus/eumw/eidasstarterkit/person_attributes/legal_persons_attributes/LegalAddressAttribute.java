/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.eidasstarterkit.person_attributes.legal_persons_attributes;

import org.xml.sax.SAXException;

import de.governikus.eumw.eidascommon.Utils;
import de.governikus.eumw.eidasstarterkit.EidasLegalPersonAttributes;
import de.governikus.eumw.eidasstarterkit.person_attributes.EidasPersonAttributes;
import de.governikus.eumw.eidasstarterkit.person_attributes.natural_persons_attribute.CurrentAddressAttribute;
import de.governikus.eumw.eidasstarterkit.template.TemplateLoader;


/**
 * Created by yuri on 2/12/2016.
 */
public class LegalAddressAttribute extends CurrentAddressAttribute
{

  public LegalAddressAttribute(String locatorDesignator,
                               String thoroughfare,
                               String postName,
                               String postCode,
                               String pOBOX,
                               String locatorName,
                               String cvaddressArea,
                               String adminunitFirstline,
                               String adminunitSecondline)
  {
    super(locatorDesignator, thoroughfare, postName, postCode, pOBOX, locatorName, cvaddressArea,
          adminunitFirstline, adminunitSecondline);
  }

  public LegalAddressAttribute(String xmlString) throws SAXException
  {
    super(xmlString);
  }

  public LegalAddressAttribute()
  {}

  @Override
  public String generate()
  {
    String value = super.getLatinScript();
    return TemplateLoader.getTemplateByName("legalpersonaddress").replace("$base64Value",
                                                                          Utils.toBase64(value));
  }

  @Override
  public EidasAttributeType type()
  {
    return EidasAttributeType.LEGAL_PERSON_ADDRESS;
  }

  @Override
  public String toString()
  {
    return type() + " " + getLocatorDesignator() + " " + getThoroughfare() + " , " + getPostCode() + " "
           + getPostName();
  }

  @Override
  public EidasPersonAttributes getPersonAttributeType()
  {
    return EidasLegalPersonAttributes.LEGAL_ADDRESS;
  }


}

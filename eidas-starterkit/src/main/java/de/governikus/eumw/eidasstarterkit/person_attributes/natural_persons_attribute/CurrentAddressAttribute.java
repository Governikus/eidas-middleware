/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.eidasstarterkit.person_attributes.natural_persons_attribute;

import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeValue;

import de.governikus.eumw.eidasstarterkit.EidasNaturalPersonAttributes;
import de.governikus.eumw.eidasstarterkit.person_attributes.AbstractEidasAttribute;
import de.governikus.eumw.eidasstarterkit.person_attributes.EidasPersonAttributes;
import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import se.litsec.eidas.opensaml.ext.attributes.CurrentAddressType;
import se.litsec.eidas.opensaml.ext.attributes.impl.CurrentAddressTypeBuilder;


@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(callSuper = false)
public class CurrentAddressAttribute extends AbstractEidasAttribute
{

  private String poBox;

  private String locatorDesignator;

  private String locatorName;

  private String cvaddressArea;

  private String thoroughfare;

  private String postName;

  private String adminunitFirstline;

  private String adminunitSecondline;

  private String postCode;

  @Override
  public EidasPersonAttributes type()
  {
    return EidasNaturalPersonAttributes.CURRENT_ADDRESS;
  }

  @Override
  public String toString()
  {
    return type().getFriendlyName() + ": [LocatorDesignator: " + this.locatorDesignator + "] [Thoroughfare: "
           + this.thoroughfare + "] [PostCode: " + this.postCode + "] [PostName: " + this.postName + "] [PoBox: "
           + this.poBox + "] [LocatorName: " + this.locatorName + "] [CvaddressArea: " + this.cvaddressArea
           + "] [AdminunitFirstline: " + this.adminunitFirstline + "] [AdminunitSecondline: "
           + this.adminunitSecondline + "]";
  }

  @Override
  public Attribute generate()
  {
    Attribute attr = super.generate();
    CurrentAddressType cat = new CurrentAddressTypeBuilder().buildObject(AttributeValue.DEFAULT_ELEMENT_NAME,
                                                                         type().getQName());
    cat.setAdminunitFirstline(adminunitFirstline);
    cat.setAdminunitSecondline(adminunitSecondline);
    cat.setCvaddressArea(cvaddressArea);
    cat.setLocatorDesignator(locatorDesignator);
    cat.setLocatorName(locatorName);
    cat.setPoBox(poBox);
    cat.setPostCode(postCode);
    cat.setPostName(postName);
    cat.setThoroughfare(thoroughfare);
    attr.getAttributeValues().add(cat);
    return attr;
  }

  public void setFromCurrentAddressType(CurrentAddressType cat)
  {
    if (cat != null)
    {
      adminunitFirstline = cat.getAdminunitFirstline();
      adminunitSecondline = cat.getAdminunitSecondline();
      cvaddressArea = cat.getCvaddressArea();
      locatorDesignator = cat.getLocatorDesignator();
      locatorName = cat.getLocatorName();
      poBox = cat.getPoBox();
      postCode = cat.getPostCode();
      postName = cat.getPostName();
      thoroughfare = cat.getThoroughfare();
    }
  }

  @Override
  public void setValue(String value)
  {
    throw new UnsupportedOperationException("simple value has no use for CurrentAddressType");
  }

  @Override
  public String getValue()
  {
    throw new UnsupportedOperationException("simple value has no use for CurrentAddressType");
  }
}

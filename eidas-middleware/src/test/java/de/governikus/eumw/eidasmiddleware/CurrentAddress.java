/*
 * Copyright (c) 2019 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.eidasmiddleware;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.xml.sax.SAXException;

import de.governikus.eumw.eidasstarterkit.person_attributes.natural_persons_attribute.CurrentAddressAttribute;


public class CurrentAddress
{

  @Before
  public void setUp() throws Exception
  {}

  @Test
  public void test() throws SAXException
  {
    String s = "<eidas:LocatorDesignator>22</eidas:LocatorDesignator>"
               + "<eidas:Thoroughfare>Arcacia Avenue</eidas:Thoroughfare>"
               + "<eidas:PostName>London</eidas:PostName> " + "<eidas:PostCode>SW1A 1AA</eidas:PostCode>";
    CurrentAddressAttribute c = new CurrentAddressAttribute(s);
    Assert.assertEquals("22", c.getLocatorDesignator());
    Assert.assertEquals("Arcacia Avenue", c.getThoroughfare());
    Assert.assertEquals("London", c.getPostName());
    Assert.assertEquals("SW1A 1AA", c.getPostCode());
    Assert.assertNull(c.getAdminunitFirstline());
    Assert.assertNull(c.getAdminunitSecondline());
  }
}

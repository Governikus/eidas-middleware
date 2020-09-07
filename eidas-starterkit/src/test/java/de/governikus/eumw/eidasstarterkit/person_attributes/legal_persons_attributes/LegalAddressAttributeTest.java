/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.eidasstarterkit.person_attributes.legal_persons_attributes;

import java.io.IOException;

import org.apache.commons.lang.StringUtils;
import org.junit.Test;
import org.junit.jupiter.api.Assertions;

import de.governikus.eumw.eidascommon.Utils;
import de.governikus.eumw.eidasstarterkit.person_attributes.natural_persons_attribute.CurrentAddressAttribute;
import de.governikus.eumw.eidasstarterkit.template.TemplateLoader;


public class LegalAddressAttributeTest
{

  @Test
  public void testGenerateLegalAddressAttribute() throws IOException
  {
    String locatorDesignator = "locatorDesignator";
    String thoroughfare = "thoroughfare";
    String postName = "postName";
    String postCode = "postCode";
    String pOBOX = "pOBOX";
    String locatorName = "locatorName";
    String cvaddressArea = "cvaddressArea";
    String adminunitFirstline = "adminunitFirstline";
    String adminunitSecondline = "adminunitSecondline";

    LegalAddressAttribute attribute = new LegalAddressAttribute(locatorDesignator, thoroughfare, postName,
                                                                postCode, pOBOX, locatorName, cvaddressArea,
                                                                adminunitFirstline, adminunitSecondline);
    TemplateLoader.init();
    String xml = attribute.generate();

    Assertions.assertTrue(StringUtils.isNotEmpty(xml));
    String substringBetween = StringUtils.substringBetween(xml,
                                                           "<saml2:AttributeValue xsi:type=\"eidas:LegalPersonAddressType\">",
                                                           "</saml2:AttributeValue>");
    Assertions.assertTrue(StringUtils.isNotEmpty(substringBetween));
    String base64Decoded = Utils.fromBase64(substringBetween);
    Assertions.assertTrue(StringUtils.isNotEmpty(base64Decoded));
    Assertions.assertTrue(base64Decoded.contains("locatorDesignator"));
    Assertions.assertTrue(base64Decoded.contains("thoroughfare"));
    Assertions.assertTrue(base64Decoded.contains("postName"));
    Assertions.assertTrue(base64Decoded.contains("postCode"));
    Assertions.assertTrue(base64Decoded.contains("locatorName"));
    Assertions.assertTrue(base64Decoded.contains("cvaddressArea"));
    Assertions.assertTrue(base64Decoded.contains("adminunitFirstline"));
    Assertions.assertTrue(base64Decoded.contains("adminunitSecondline"));
  }

  @Test
  public void testGenerateCurrentAddressAttribute() throws IOException
  {
    String locatorDesignator = "locatorDesignator";
    String thoroughfare = "thoroughfare";
    String postName = "postName";
    String postCode = "postCode";
    String pOBOX = "pOBOX";
    String locatorName = "locatorName";
    String cvaddressArea = "cvaddressArea";
    String adminunitFirstline = "adminunitFirstline";
    String adminunitSecondline = "adminunitSecondline";

    CurrentAddressAttribute attribute = new CurrentAddressAttribute(locatorDesignator, thoroughfare, postName,
                                                                    postCode, pOBOX, locatorName,
                                                                    cvaddressArea, adminunitFirstline,
                                                                    adminunitSecondline);
    TemplateLoader.init();
    String xml = attribute.generate();

    Assertions.assertTrue(StringUtils.isNotEmpty(xml));
    String substringBetween = StringUtils.substringBetween(xml,
                                                           "<saml2:AttributeValue xsi:type=\"eidas:CurrentAddressType\">",
                                                           "</saml2:AttributeValue>");
    Assertions.assertTrue(StringUtils.isNotEmpty(substringBetween));
    String base64Decoded = Utils.fromBase64(substringBetween);
    Assertions.assertTrue(StringUtils.isNotEmpty(base64Decoded));
    Assertions.assertTrue(base64Decoded.contains("locatorDesignator"));
    Assertions.assertTrue(base64Decoded.contains("thoroughfare"));
    Assertions.assertTrue(base64Decoded.contains("postName"));
    Assertions.assertTrue(base64Decoded.contains("postCode"));
    Assertions.assertTrue(base64Decoded.contains("locatorName"));
    Assertions.assertTrue(base64Decoded.contains("cvaddressArea"));
    Assertions.assertTrue(base64Decoded.contains("adminunitFirstline"));
    Assertions.assertTrue(base64Decoded.contains("adminunitSecondline"));
  }
}

/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.eidasmiddleware;

import java.io.IOException;
import java.io.InputStream;

import org.junit.Assert;
import org.junit.jupiter.api.Test;
import org.opensaml.core.config.InitializationException;
import org.xml.sax.SAXException;

import de.governikus.eumw.eidasstarterkit.EidasSaml;



public class SamlShemaValidationTest
{

  @Test
  void test() throws SAXException, IOException, InitializationException
  {
    EidasSaml.init();

    try (InputStream is = SamlShemaValidationTest.class.getResourceAsStream("posAuthReq.xml"))
    {
      EidasSaml.validateXMLRequest(is, false);
    }

    try (InputStream is = SamlShemaValidationTest.class.getResourceAsStream("negAuthReq.xml"))
    {
      EidasSaml.validateXMLRequest(is, false);
      Assert.fail();
    }
    catch (SAXException _)
    {
      // this is okay
    }
  }
}

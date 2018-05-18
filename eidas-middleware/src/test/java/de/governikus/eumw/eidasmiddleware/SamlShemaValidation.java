/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.eidasmiddleware;

import java.io.IOException;
import java.io.InputStream;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.xml.sax.SAXException;

import de.governikus.eumw.eidasstarterkit.EidasSaml;



public class SamlShemaValidation
{

  @Before
  public void setUp() throws Exception
  {
    EidasSaml.init();
  }

  @Test
  public void test() throws SAXException, IOException
  {

    try (InputStream is = SamlShemaValidation.class.getResourceAsStream("posAuthReq.xml"))
    {
      EidasSaml.validateXMLRequest(is, false);
    }

    try (InputStream is = SamlShemaValidation.class.getResourceAsStream("negAuthReq.xml"))
    {
      EidasSaml.validateXMLRequest(is, false);
      Assert.fail();
    }
    catch (SAXException e)
    {
      // this is okay
    }
    catch (IOException e)
    {
      throw e;
    }
  }
}

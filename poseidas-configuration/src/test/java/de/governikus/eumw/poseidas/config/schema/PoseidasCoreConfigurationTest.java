/*
 * Copyright (c) 2019 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.config.schema;

import java.io.IOException;

import org.apache.commons.io.IOUtils;
import org.junit.Assert;
import org.junit.jupiter.api.Test;

import de.governikus.eumw.utils.xml.XmlHelper;



/**
 * project: eumw <br>
 *
 * @author Pascal Knueppel <br>
 *         created at: 09.02.2018 - 13:02 <br>
 *         <br>
 */
public class PoseidasCoreConfigurationTest
{

  /**
   * this test will assert that {@link PoseidasCoreConfiguration} can be marshalled and unmarshalled
   * successfully as as {@link CoreConfigurationType}
   */
  @Test
  public void testMarshallingOfPoseidasCoreConfiguration() throws IOException
  {
    String xml = IOUtils.toString(getClass().getResourceAsStream("/test-xml/POSeIDAS.xml"), "UTF-8");
    PoseidasCoreConfiguration coreConfiguration = XmlHelper.unmarshal(xml, PoseidasCoreConfiguration.class);
    Assert.assertNotNull(coreConfiguration);
    xml = XmlHelper.marshalObject(coreConfiguration);
    Assert.assertNotNull(xml);
  }

}

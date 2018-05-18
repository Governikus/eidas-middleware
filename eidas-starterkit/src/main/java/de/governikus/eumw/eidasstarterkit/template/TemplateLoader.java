/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.eidasstarterkit.template;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;


public class TemplateLoader
{

  private static boolean isInit = false;

  private static HashMap<String, String> map;

  // avoid construction
  private TemplateLoader()
  {
    super();
  }

  public static synchronized void init() throws IOException
  {
    if (!isInit)
    {
      map = new HashMap<>();

      map.put("personId", streamToString(TemplateLoader.class.getResourceAsStream("personId_template.xml")));
      map.put("dateOfBirth",
              streamToString(TemplateLoader.class.getResourceAsStream("dateOfBirth_template.xml")));
      map.put("familyname",
              streamToString(TemplateLoader.class.getResourceAsStream("familyname_template.xml")));
      map.put("givenname",
              streamToString(TemplateLoader.class.getResourceAsStream("givenname_template.xml")));
      map.put("givenname_transliterated",
              streamToString(TemplateLoader.class.getResourceAsStream("givenname_transliterated_template.xml")));
      map.put("asso", streamToString(TemplateLoader.class.getResourceAsStream("asso_template.xml")));
      map.put("resp", streamToString(TemplateLoader.class.getResourceAsStream("resp_template.xml")));
      map.put("familyname_transliterated",
              streamToString(TemplateLoader.class.getResourceAsStream("familyname_transliterated_template.xml")));
      map.put("auth", streamToString(TemplateLoader.class.getResourceAsStream("auth_template.xml")));
      map.put("metadataservice",
              streamToString(TemplateLoader.class.getResourceAsStream("metadata_service_template.xml")));
      map.put("gender", streamToString(TemplateLoader.class.getResourceAsStream("gender_template.xml")));
      map.put("birthName",
              streamToString(TemplateLoader.class.getResourceAsStream("birthName_Template.xml")));
      map.put("birthName_transliterated",
              streamToString(TemplateLoader.class.getResourceAsStream("birthName_transliterated_Template.xml")));
      map.put("currentAddress",
              streamToString(TemplateLoader.class.getResourceAsStream("currentaddress_template.xml")));
      map.put("placeOfBirth",
              streamToString(TemplateLoader.class.getResourceAsStream("placeOfBirth_template.xml")));
      map.put("metadatanode",
              streamToString(TemplateLoader.class.getResourceAsStream("metadata_nodes_template.xml")));
      map.put("failresp", streamToString(TemplateLoader.class.getResourceAsStream("fail_resp_template.xml")));
      map.put("failasso", streamToString(TemplateLoader.class.getResourceAsStream("fail_asso_template.xml")));

      map.put("d201217euidentifier",
              streamToString(TemplateLoader.class.getResourceAsStream("d201217euidentifier_template.xml")));
      map.put("eori", streamToString(TemplateLoader.class.getResourceAsStream("eori_template.xml")));
      map.put("legalentityidentifier",
              streamToString(TemplateLoader.class.getResourceAsStream("legalentityidentifier_template.xml")));
      map.put("legalname",
              streamToString(TemplateLoader.class.getResourceAsStream("legalname_template.xml")));
      map.put("legalname_transliterated",
              streamToString(TemplateLoader.class.getResourceAsStream("legalname_transliterated_template.xml")));

      map.put("legalpersonaddress",
              streamToString(TemplateLoader.class.getResourceAsStream("legalpersonaddress_template.xml")));
      map.put("legalpersonidentifier",
              streamToString(TemplateLoader.class.getResourceAsStream("legalpersonidentifier_template.xml")));
      map.put("seed", streamToString(TemplateLoader.class.getResourceAsStream("seed_template.xml")));
      map.put("sic", streamToString(TemplateLoader.class.getResourceAsStream("sic_template.xml")));
      map.put("taxreference",
              streamToString(TemplateLoader.class.getResourceAsStream("taxreference_template.xml")));
      map.put("vatregistration",
              streamToString(TemplateLoader.class.getResourceAsStream("vatregistration_template.xml")));
      isInit = true;
    }
  }

  /**
   * Getter
   * 
   * @param name
   * @return
   */
  public static synchronized String getTemplateByName(String name)
  {
    return map.get(name);
  }

  private static String streamToString(InputStream ins) throws IOException
  {
    byte[] inBytes = new byte[1024];
    byte[] returnVaue;
    try (ByteArrayOutputStream outs = new ByteArrayOutputStream())
    {
      int numReadBytes = ins.read(inBytes);

      while (numReadBytes > 0)
      {
        outs.write(inBytes, 0, numReadBytes);
        numReadBytes = ins.read(inBytes);
      }
      returnVaue = outs.toByteArray();
    }
    return new String(returnVaue, StandardCharsets.UTF_8);
  }
}

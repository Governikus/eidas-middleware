/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.ecardcore.utilities;

import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import de.governikus.eumw.eidascommon.Utils;
import iso.std.iso_iec._24727.tech.schema.DIDAuthenticationDataType;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;


@Slf4j
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class EACElementUtil
{

  public static final String ATTRIBUTE_TYPE = "type";


  public static final void addElement(DIDAuthenticationDataType intData,
                                      int index,
                                      String name,
                                      String content)
  {
    addElement(intData, index, name, null, content);
  }

  public static final void addElement(DIDAuthenticationDataType intData,
                                      int index,
                                      String name,
                                      String type,
                                      String content)
  {
    try
    {
      Document doc = Utils.getDocumentBuilder().newDocument();
      Element e = doc.createElementNS("urn:iso:std:iso-iec:24727:tech:schema", name);
      if (type != null)
      {
        e.setAttribute(ATTRIBUTE_TYPE, type);
      }
      e.setTextContent(content);
      intData.getAny().add(index, e);
    }
    catch (ParserConfigurationException e)
    {
      if (log.isDebugEnabled())
      {
        log.debug("Failed to get document builder", e);
      }
      // nothing
    }
  }
}

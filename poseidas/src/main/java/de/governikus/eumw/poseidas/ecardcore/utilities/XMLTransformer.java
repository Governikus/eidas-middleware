/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.ecardcore.utilities;

import java.io.StringWriter;

import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;


/**
 * Helper to transform a document to XML-file and vice versa
 * 
 * @author Thomas Chojecki
 */

public class XMLTransformer
{

  private static TransformerFactory tf = TransformerFactory.newInstance();

  private XMLTransformer()
  {}

  /**
   * converts the xml <code>Document</code> to a String
   * 
   * @param document xml <code>Document</code>
   * @throws TransformerException
   */
  public static String xmlToString(Document document) throws TransformerException
  {
    Transformer t = tf.newTransformer();
    t.setOutputProperty(OutputKeys.INDENT, "yes");
    t.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");

    StringWriter stringWriter = new StringWriter();
    t.transform(new DOMSource(document), new StreamResult(stringWriter));
    return stringWriter.toString();
  }
}

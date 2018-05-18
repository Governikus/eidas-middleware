/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.eidservice;

import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;

import com.sun.xml.ws.developer.ValidationErrorHandler;


public class SchemaValidationHandler extends ValidationErrorHandler
{

  static final String XML_ERROR = "XMLParseError";

  @Override
  public void warning(SAXParseException exception) throws SAXException
  {
    // nothing
  }

  @Override
  public void error(SAXParseException exception) throws SAXException
  {
    packet.invocationProperties.put(XML_ERROR, exception);
  }

  @Override
  public void fatalError(SAXParseException exception) throws SAXException
  {
    packet.invocationProperties.put(XML_ERROR, exception);
  }
}

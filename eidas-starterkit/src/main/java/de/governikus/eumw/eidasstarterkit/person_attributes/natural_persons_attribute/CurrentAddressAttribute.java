/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.eidasstarterkit.person_attributes.natural_persons_attribute;

import java.io.ByteArrayInputStream;
import java.io.IOException;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;

import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

import de.governikus.eumw.eidascommon.Utils;
import de.governikus.eumw.eidasstarterkit.EidasAttribute;
import de.governikus.eumw.eidasstarterkit.EidasNaturalPersonAttributes;
import de.governikus.eumw.eidasstarterkit.person_attributes.EidasPersonAttributes;
import de.governikus.eumw.eidasstarterkit.template.TemplateLoader;


public class CurrentAddressAttribute implements EidasAttribute
{

  private static final String CV_ADDRESS_TEMP = "<eidas:PoBox>$pOBOX</eidas:PoBox>"
                                                +"<eidas:LocatorDesignator>$locatorDesignator</eidas:LocatorDesignator>"
                                                + "<eidas:LocatorName>$locatorName</eidas:LocatorName>"
                                                + "<eidas:CvaddressArea>$cvaddressArea</eidas:CvaddressArea>"
                                                + "<eidas:Thoroughfare>$thoroughfare</eidas:Thoroughfare>"
                                                + "<eidas:PostName>$postName</eidas:PostName>"
                                                + "<eidas:AdminunitFirstline>$adminunitFirstline</eidas:AdminunitFirstline>"
                                                + "<eidas:AdminunitSecondline>$adminunitSecondline</eidas:AdminunitSecondline>"
                                                + "<eidas:PostCode>$postCode</eidas:PostCode>";

  private String locatorDesignator;

  private String thoroughfare;

  private String postName;

  private String postCode;

  private String pOBOX;

  private String locatorName;

  private String cvaddressArea;

  private String adminunitSecondline;

  private String adminunitFirstline;

  public CurrentAddressAttribute()
  {}

  public CurrentAddressAttribute(String locatorDesignator,
                                 String thoroughfare,
                                 String postName,
                                 String postCode,
                                 String pOBOX,
                                 String locatorName,
                                 String cvaddressArea,
                                 String adminunitFirstline,
                                 String adminunitSecondline)
  {
    super();
    this.locatorDesignator = locatorDesignator;
    this.thoroughfare = thoroughfare;
    this.postName = postName;
    this.postCode = postCode;
    this.pOBOX = pOBOX;
    this.locatorName = locatorName;
    this.cvaddressArea = cvaddressArea;
    this.adminunitFirstline = adminunitFirstline;
    this.adminunitSecondline = adminunitSecondline;
  }

  /**
   * Adds a root XML Container around the given CurrentAddressAttribute. Otherwise the XML is not well formed
   * and will raise an exception
   * 
   * @param xmlString
   * @throws SAXException
   */
  public CurrentAddressAttribute(String xmlString) throws SAXException
  {
    parseXML(xmlString);
  }

  /**
   * Decode and parse the given xml string. Adds a root XML Container around the given
   * CurrentAddressAttribute. Otherwise the XML is not well formed and will raise an exception
   * 
   * @param base64XmlString base64 encoded xmlstring
   */
  private void parseEncodedXML(String base64XmlString) throws SAXException
  {
    parseXML(Utils.fromBase64(base64XmlString));
  }

  /**
   * parse the given xml string. Adds a root XML Container around the given CurrentAddressAttribute. Otherwise
   * the XML is not well formed and will raise an exception
   * 
   * @param xmlString
   */
  private void parseXML(String xmlString) throws SAXException
  {
    SAXParserFactory factory = SAXParserFactory.newInstance();
    try
    {
      String xml = "<root>" + xmlString + "</root>";
      SAXParser saxParser = factory.newSAXParser();
      AddressAttributeXMLHandler handler = new AddressAttributeXMLHandler();
      saxParser.parse(new ByteArrayInputStream(xml.getBytes("UTF-8")), handler);
      this.locatorDesignator = handler.locatorDesignator;
      this.thoroughfare = handler.thoroughfare;
      this.postName = handler.postName;
      this.postCode = handler.postCode;
      this.pOBOX = handler.pOBOX;
      this.locatorName = handler.locatorName;
      this.locatorDesignator = handler.locatorDesignator;
      this.cvaddressArea = handler.cvaddressArea;
      this.adminunitFirstline = handler.adminunitFirstline;
      this.adminunitSecondline = handler.adminunitSecondline;
    }
    catch (ParserConfigurationException | SAXException | IOException e)
    {
      throw new SAXException(e);
    }

  }

  public String getLocatorDesignator()
  {
    return locatorDesignator;
  }

  public void setLocatorDesignator(String locatorDesignator)
  {
    this.locatorDesignator = locatorDesignator;
  }

  public String getThoroughfare()
  {
    return thoroughfare;
  }

  public void setThoroughfare(String thoroughfare)
  {
    this.thoroughfare = thoroughfare;
  }

  public String getPostName()
  {
    return postName;
  }

  public void setPostName(String postName)
  {
    this.postName = postName;
  }

  public String getPostCode()
  {
    return postCode;
  }

  public void setPostCode(String postCode)
  {
    this.postCode = postCode;
  }

  public String getpOBOX()
  {
    return pOBOX;
  }

  public void setpOBOX(String pOBOX)
  {
    this.pOBOX = pOBOX;
  }

  public String getLocatorName()
  {
    return locatorName;
  }

  public void setLocatorName(String locatorName)
  {
    this.locatorName = locatorName;
  }

  public String getCvaddressArea()
  {
    return cvaddressArea;
  }

  public void setCvaddressArea(String cvaddressArea)
  {
    this.cvaddressArea = cvaddressArea;
  }

  public String getAdminunitSecondline()
  {
    return adminunitSecondline;
  }

  public void setAdminunitSecondline(String adminunitSecondline)
  {
    this.adminunitSecondline = adminunitSecondline;
  }

  public String getAdminunitFirstline()
  {
    return adminunitFirstline;
  }

  public void setAdminunitFirstline(String adminunitFirstline)
  {
    this.adminunitFirstline = adminunitFirstline;
  }

  @Override
  public String generate()
  {
    String value = getLatinScript();
    return TemplateLoader.getTemplateByName("currentAddress").replace("$value", Utils.toBase64(value));
  }

  @Override
  public EidasAttributeType type()
  {
    return EidasAttributeType.CURRENT_ADDRESS;
  }

  @Override
  public String toString()
  {
    return type() + " " + this.locatorDesignator + " " + this.thoroughfare + " , " + this.postCode + " "
           + this.postName + " " + this.pOBOX + " " + this.locatorName + " " + this.locatorDesignator + " "
           + this.cvaddressArea + " " + this.adminunitFirstline + " " + this.adminunitSecondline;
  }

  @Override
  public EidasPersonAttributes getPersonAttributeType()
  {
    return EidasNaturalPersonAttributes.CURRENT_ADDRESS;
  }

  /**
   * the given value will parsed by parseEncodedXML(String)
   */
  @Override
  public void setLatinScript(String value)
  {
    try
    {
      parseEncodedXML(value);
    }
    catch (Exception e)
    {
      // nothing
    }
  }

  @Override
  public String getLatinScript()
  {
    return CV_ADDRESS_TEMP.replace("$locatorDesignator",
                                 getLocatorDesignator() == null ? "" : getLocatorDesignator())
                        .replace("$thoroughfare", getThoroughfare() == null ? "" : getThoroughfare())
                        .replace("$postName", getPostName() == null ? "" : getPostName())
                        .replace("$postCode", getPostCode() == null ? "" : getPostCode())
                        .replace("$pOBOX", getpOBOX() == null ? "" : getpOBOX())
                        .replace("$locatorName", getLocatorName() == null ? "" : getLocatorName())
                        .replace("$cvaddressArea", getCvaddressArea() == null ? "" : getCvaddressArea())
                        .replace("$adminunitFirstline",
                                 getAdminunitFirstline() == null ? "" : getAdminunitFirstline())
                        .replace("$adminunitSecondline",
                                 getAdminunitSecondline() == null ? "" : getAdminunitSecondline());
  }

  private class AddressAttributeXMLHandler extends DefaultHandler
  {

    private String locatorDesignator = "";

    private String thoroughfare = "";

    private String postName = "";

    private String postCode = "";

    private String pOBOX = "";

    private String locatorName = "";

    private String cvaddressArea = "";

    private String adminunitSecondline = "";

    private String adminunitFirstline = "";

    private String currentQName = "";


    @Override
    public void startElement(String uri, String localName, String qName, Attributes attributes)
      throws SAXException
    {
      currentQName = qName.toLowerCase();
    }

    @Override
    public void characters(char[] ch, int start, int length) throws SAXException
    {
      String value = new String(ch, start, length).trim();
      if (Utils.isNullOrEmpty(value))
      {
        return;
      }
      if (currentQName.contains("locatordesignator"))
      {
        locatorDesignator = value;
        return;
      }
      else if (currentQName.contains("thoroughfare"))
      {
        thoroughfare = value;
        return;
      }
      else if (currentQName.contains("postname"))
      {
        postName = value;
        return;
      }
      else if (currentQName.contains("postcode"))
      {
        postCode = value;
        return;
      }
      else if (currentQName.contains("pobox"))
      {
        pOBOX = value;
        return;
      }
      else if (currentQName.contains("locatorname"))
      {
        locatorName = value;
        return;
      }
      else if (currentQName.contains("cvaddressarea"))
      {
        cvaddressArea = value;
        return;
      }
      else if (currentQName.contains("adminunitsecondline"))
      {
        adminunitSecondline = value;
        return;
      }
      else if (currentQName.contains("adminunitfirstline"))
      {
        adminunitFirstline = value;
        return;
      }
    }
  }
}

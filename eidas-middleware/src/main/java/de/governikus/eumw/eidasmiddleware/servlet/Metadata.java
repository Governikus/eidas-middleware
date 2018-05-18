/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.eidasmiddleware.servlet;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateEncodingException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactoryConfigurationError;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.xmlsec.signature.support.SignatureException;

import de.governikus.eumw.eidascommon.Utils;
import de.governikus.eumw.eidasmiddleware.ConfigHolder;
import de.governikus.eumw.eidasstarterkit.Constants;
import de.governikus.eumw.eidasstarterkit.EidasNameIdType;
import de.governikus.eumw.eidasstarterkit.EidasNaturalPersonAttributes;
import de.governikus.eumw.eidasstarterkit.EidasSaml;
import de.governikus.eumw.eidasstarterkit.EidasSigner;
import de.governikus.eumw.eidasstarterkit.person_attributes.EidasPersonAttributes;


/**
 * Servlet implementation class Metadata
 */
@WebServlet("/Metadata")
public class Metadata extends HttpServlet
{

  private static final long serialVersionUID = 1L;

  private static final Log LOG = LogFactory.getLog(Metadata.class);

  /**
   * @see HttpServlet#HttpServlet()
   */
  public Metadata()
  {
    super();
  }

  public void sendMetadata(HttpServletRequest request, HttpServletResponse response)
  {
    String serverurl = Utils.createOwnUrlPrefix(request);
    String path = request.getRequestURI().replace("Metadata", "RequestReceiver");
    ArrayList<EidasPersonAttributes> list = new ArrayList<>();
    list.add(EidasNaturalPersonAttributes.FAMILY_NAME);
    list.add(EidasNaturalPersonAttributes.FIRST_NAME);
    list.add(EidasNaturalPersonAttributes.CURRENT_ADDRESS);
    list.add(EidasNaturalPersonAttributes.PERSON_IDENTIFIER);
    list.add(EidasNaturalPersonAttributes.BIRTH_NAME);
    list.add(EidasNaturalPersonAttributes.PLACE_OF_BIRTH);
    list.add(EidasNaturalPersonAttributes.DATE_OF_BIRTH);
    EidasSigner signer = new EidasSigner(true, ConfigHolder.getSignatureKey(),
                                         ConfigHolder.getSignatureCert());
    List<EidasNameIdType> supportedNameIdTypes = new ArrayList<>();
    supportedNameIdTypes.add(EidasNameIdType.PERSISTENT);
    supportedNameIdTypes.add(EidasNameIdType.TRANSIENT);
    supportedNameIdTypes.add(EidasNameIdType.UNSPECIFIED);
    try
    {
      byte[] out = EidasSaml.createMetaDataService("_eumiddleware",
                                                   request.getRequestURL().toString(),
                                                   Constants.parse("2020-12-31T0:00:00.000Z"),
                                                   ConfigHolder.getSignatureCert(),
                                                   ConfigHolder.getDecryptionCert(),
                                                   ConfigHolder.getOrganization(),
                                                   ConfigHolder.getContactPerson(),
                                                   ConfigHolder.getContactPerson(),
                                                   serverurl + path,
                                                   serverurl + path,
                                                   supportedNameIdTypes,
                                                   list,
                                                   signer);

      response.getWriter().write(new String(out, StandardCharsets.UTF_8));
      response.setContentType("application/xml");
      response.setCharacterEncoding("UTF-8");
      return;
    }
    catch (ParseException | CertificateEncodingException | MarshallingException | SignatureException
      | TransformerFactoryConfigurationError | TransformerException | InitializationException | IOException e)
    {
      LOG.error("", e);
    }
    response.setStatus(500);
  }

  /**
   * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
   */
  @Override
  protected void doGet(HttpServletRequest request, HttpServletResponse response)
  {
    sendMetadata(request, response);
  }

  /**
   * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse response)
   */
  @Override
  protected void doPost(HttpServletRequest request, HttpServletResponse response)
  {
    sendMetadata(request, response);
  }
}

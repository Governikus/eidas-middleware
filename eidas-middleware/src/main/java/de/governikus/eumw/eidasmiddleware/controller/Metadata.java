/*
 * Copyright (c) 2019 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.eidasmiddleware.controller;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.TimeZone;

import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactoryConfigurationError;

import org.opensaml.core.config.InitializationException;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import de.governikus.eumw.eidascommon.ContextPaths;
import de.governikus.eumw.eidasmiddleware.ConfigHolder;
import de.governikus.eumw.eidasstarterkit.EidasNameIdType;
import de.governikus.eumw.eidasstarterkit.EidasNaturalPersonAttributes;
import de.governikus.eumw.eidasstarterkit.EidasSaml;
import de.governikus.eumw.eidasstarterkit.EidasSigner;
import de.governikus.eumw.eidasstarterkit.person_attributes.EidasPersonAttributes;
import de.governikus.eumw.poseidas.server.pki.HSMServiceHolder;
import lombok.extern.slf4j.Slf4j;


/**
 * Servlet implementation class Metadata
 */
@Slf4j
@Controller
@RequestMapping(ContextPaths.EIDAS_CONTEXT_PATH + ContextPaths.METADATA)
public class Metadata
{

  private final ConfigHolder configHolder;

  @Autowired
  private HSMServiceHolder hsmServiceHolder;

  public Metadata(ConfigHolder configHolder)
  {
    this.configHolder = configHolder;
  }

  /**
   * Return the SAML Metadata for this middleware
   */
  @GetMapping(produces = MediaType.APPLICATION_XML_VALUE)
  public ResponseEntity<String> sendMetadata()
  {
    ArrayList<EidasPersonAttributes> list = new ArrayList<>();
    list.add(EidasNaturalPersonAttributes.FAMILY_NAME);
    list.add(EidasNaturalPersonAttributes.FIRST_NAME);
    list.add(EidasNaturalPersonAttributes.CURRENT_ADDRESS);
    list.add(EidasNaturalPersonAttributes.PERSON_IDENTIFIER);
    list.add(EidasNaturalPersonAttributes.BIRTH_NAME);
    list.add(EidasNaturalPersonAttributes.PLACE_OF_BIRTH);
    list.add(EidasNaturalPersonAttributes.DATE_OF_BIRTH);

    List<EidasNameIdType> supportedNameIdTypes = new ArrayList<>();
    supportedNameIdTypes.add(EidasNameIdType.PERSISTENT);
    supportedNameIdTypes.add(EidasNameIdType.TRANSIENT);
    supportedNameIdTypes.add(EidasNameIdType.UNSPECIFIED);
    try
    {
      EidasSigner signer = getEidasSigner();

      Date validUntil;
      if (configHolder.getMetadataValidity() == null)
      {
        // 86400000 milliseconds per day
        validUntil = new Date(System.currentTimeMillis() + 30L * 86400000L);
      }
      else
      {
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");
        sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
        validUntil = sdf.parse(configHolder.getMetadataValidity());
      }
      byte[] out = EidasSaml.createMetaDataService("_eumiddleware",
                                                   configHolder.getServerURLWithContextPath()
                                                                    + ContextPaths.METADATA,
                                                   validUntil,
                                                   signer.getSigCert(),
                                                   configHolder.getDecryptionCert(),
                                                   configHolder.getOrganization(),
                                                   configHolder.getContactPerson(),
                                                   configHolder.getContactPerson(),
                                                   configHolder.getServerURLWithContextPath() + ContextPaths.REQUEST_RECEIVER,
                                                   configHolder.getServerURLWithContextPath() + ContextPaths.REQUEST_RECEIVER,
                                                   supportedNameIdTypes,
                                                   list,
                                                   signer);

      return new ResponseEntity<>(new String(out, StandardCharsets.UTF_8), HttpStatus.OK);
    }
    catch (ParseException | CertificateEncodingException | MarshallingException | SignatureException
      | TransformerFactoryConfigurationError | TransformerException | InitializationException | IOException
      | UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException e)
    {
      log.error("Cannot create metadata for this middleware", e);
    }
    return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
  }

  private EidasSigner getEidasSigner()
    throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException
  {
    EidasSigner signer;
    if (hsmServiceHolder.getKeyStore() == null)
    {
      signer = new EidasSigner(true, configHolder.getSignatureKey(), configHolder.getSignatureCert());
    }
    else
    {
      signer = new EidasSigner(hsmServiceHolder.getKeyStore());
    }
    return signer;
  }
}

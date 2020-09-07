/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.eidasmiddleware;

import java.io.IOException;
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

import org.apache.commons.lang3.ArrayUtils;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.springframework.boot.info.BuildProperties;
import org.springframework.stereotype.Service;

import de.governikus.eumw.eidascommon.ContextPaths;
import de.governikus.eumw.eidasstarterkit.EidasNameIdType;
import de.governikus.eumw.eidasstarterkit.EidasNaturalPersonAttributes;
import de.governikus.eumw.eidasstarterkit.EidasSaml;
import de.governikus.eumw.eidasstarterkit.EidasSigner;
import de.governikus.eumw.eidasstarterkit.person_attributes.EidasPersonAttributes;
import de.governikus.eumw.poseidas.server.pki.HSMServiceHolder;
import de.governikus.eumw.poseidas.service.MetadataService;
import lombok.extern.slf4j.Slf4j;


/**
 * This class is an implementation of {@link MetadataService} and generates the metadata for the
 * eIDAS-Middleware.
 */

@Slf4j
@Service
public class MetadataServiceImpl implements MetadataService
{

  private final HSMServiceHolder hsmServiceHolder;

  private final ConfigHolder configHolder;

  private final BuildProperties buildProperties;

  public MetadataServiceImpl(ConfigHolder configHolder,
                             BuildProperties buildProperties,
                             HSMServiceHolder hsmServiceHolder)
  {
    this.configHolder = configHolder;
    this.buildProperties = buildProperties;
    this.hsmServiceHolder = hsmServiceHolder;
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public byte[] getMetadata()
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
      String middlewareVersion = buildProperties.getVersion();
      boolean requesterIdFlag = true;
      return EidasSaml.createMetaDataService("_eumiddleware",
                                             configHolder.getServerURLWithContextPath()
                                                              + ContextPaths.METADATA,
                                             validUntil,
                                             signer.getSigCert(),
                                             configHolder.getDecryptionCert(),
                                             configHolder.getOrganization(),
                                             configHolder.getContactPerson(),
                                             configHolder.getContactPerson(),
                                             configHolder.getServerURLWithContextPath()
                                                                              + ContextPaths.REQUEST_RECEIVER,
                                             configHolder.getServerURLWithContextPath() + ContextPaths.REQUEST_RECEIVER,
                                             supportedNameIdTypes,
                                             list,
                                             signer,
                                             middlewareVersion,
                                             configHolder.isDoSignMetadata(),
                                             requesterIdFlag);
    }
    catch (ParseException | CertificateEncodingException | MarshallingException | SignatureException
      | TransformerFactoryConfigurationError | TransformerException | InitializationException | IOException
      | UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException e)
    {
      log.error("Cannot create metadata for this middleware", e);
    }
    return ArrayUtils.EMPTY_BYTE_ARRAY;
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

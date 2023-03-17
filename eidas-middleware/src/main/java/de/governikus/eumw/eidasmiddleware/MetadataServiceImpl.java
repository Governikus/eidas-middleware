/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.eidasmiddleware;

import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.ArrayUtils;
import org.springframework.boot.info.BuildProperties;
import org.springframework.stereotype.Service;

import de.governikus.eumw.config.EidasMiddlewareConfig;
import de.governikus.eumw.config.EidasMiddlewareConfig.EidasConfiguration;
import de.governikus.eumw.eidascommon.ContextPaths;
import de.governikus.eumw.eidasmiddleware.mapper.EidasMapper;
import de.governikus.eumw.eidasstarterkit.EidasNameIdType;
import de.governikus.eumw.eidasstarterkit.EidasNaturalPersonAttributes;
import de.governikus.eumw.eidasstarterkit.EidasSaml;
import de.governikus.eumw.eidasstarterkit.EidasSigner;
import de.governikus.eumw.eidasstarterkit.person_attributes.EidasPersonAttributes;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationService;
import de.governikus.eumw.poseidas.server.pki.HSMServiceHolder;
import de.governikus.eumw.poseidas.service.MetadataService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;


/**
 * This class is an implementation of {@link MetadataService} and generates the metadata for the eIDAS-Middleware.
 */

@Slf4j
@Service
@RequiredArgsConstructor
public class MetadataServiceImpl implements MetadataService
{

  private final BuildProperties buildProperties;

  private final HSMServiceHolder hsmServiceHolder;

  private final ConfigurationService configurationService;

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
    supportedNameIdTypes.add(EidasNameIdType.TRANSIENT);
    supportedNameIdTypes.add(EidasNameIdType.PERSISTENT);
    supportedNameIdTypes.add(EidasNameIdType.UNSPECIFIED);
    try
    {
      var optionalEidasMiddlewareConfig = configurationService.getConfiguration();
      if (optionalEidasMiddlewareConfig.isEmpty())
      {
        log.debug("Cannot create middleware metadata without a configuration");
        return ArrayUtils.EMPTY_BYTE_ARRAY;
      }
      var eidasMiddlewareConfig = optionalEidasMiddlewareConfig.get();
      EidasSigner signer = getEidasSigner(eidasMiddlewareConfig);

      Instant validUntil;
      if (eidasMiddlewareConfig.getEidasConfiguration().getMetadataValidity() == 0)
      {
        validUntil = Instant.now().plus(30, ChronoUnit.DAYS);
      }
      else
      {
        validUntil = Instant.now()
                            .plus(eidasMiddlewareConfig.getEidasConfiguration().getMetadataValidity(), ChronoUnit.DAYS);
      }
      String middlewareVersion = buildProperties.getVersion();
      boolean requesterIdFlag = true;
      return EidasSaml.createMetaDataService("_eumiddleware",
                                             configurationService.getServerURLWithEidasContextPath()
                                                              + ContextPaths.METADATA,
                                             validUntil,
                                             signer.getSigCert(),
                                             configurationService.getKeyPair(eidasMiddlewareConfig.getEidasConfiguration()
                                                                                                  .getDecryptionKeyPairName())
                                                                 .getCertificate(),
                                             EidasMapper.toEidasOrganisation(eidasMiddlewareConfig.getEidasConfiguration()
                                                                                                  .getOrganization()),
                                             EidasMapper.toEidasContactPerson(eidasMiddlewareConfig.getEidasConfiguration()
                                                                                                   .getContactPerson()),
                                             EidasMapper.toEidasContactPerson(eidasMiddlewareConfig.getEidasConfiguration()
                                                                                                   .getContactPerson()),
                                             configurationService.getServerURLWithEidasContextPath() + ContextPaths.REQUEST_RECEIVER,
                                             configurationService.getServerURLWithEidasContextPath() + ContextPaths.REQUEST_RECEIVER,
                                             supportedNameIdTypes,
                                             list,
                                             signer,
                                             middlewareVersion,
                                             eidasMiddlewareConfig.getEidasConfiguration().isDoSign(),
                                             requesterIdFlag,
                                             // Country Code is always 'DE' for eIDAS-Service metadata.
                                             "DE");

    }
    catch (Exception e)
    {
      log.error("Cannot create metadata for this middleware", e);
    }
    return ArrayUtils.EMPTY_BYTE_ARRAY;
  }

  private EidasSigner getEidasSigner(EidasMiddlewareConfig eidasMiddlewareConfig)
    throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException
  {
    EidasSigner signer;
    if (hsmServiceHolder.getKeyStore() == null)
    {
      signer = new EidasSigner(true,
                               configurationService.getKeyPair(eidasMiddlewareConfig.getEidasConfiguration()
                                                                                    .getSignatureKeyPairName())
                                                   .getKey(),
                               configurationService.getKeyPair(eidasMiddlewareConfig.getEidasConfiguration()
                                                                                    .getSignatureKeyPairName())
                                                   .getCertificate());
    }
    else
    {
      signer = new EidasSigner(hsmServiceHolder.getKeyStore());
    }
    return signer;
  }

}

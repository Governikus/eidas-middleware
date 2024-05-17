package de.governikus.eumw.poseidas.config;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

import de.governikus.eumw.config.CertificateType;
import de.governikus.eumw.config.DvcaConfigurationType;
import de.governikus.eumw.config.EidasMiddlewareConfig;
import de.governikus.eumw.config.KeyPairType;
import de.governikus.eumw.config.KeyStoreType;
import de.governikus.eumw.config.ServiceProviderType;
import de.governikus.eumw.eidascommon.ContextPaths;
import de.governikus.eumw.poseidas.eidserver.crl.CertificationRevocationListImpl;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationService;
import de.governikus.eumw.poseidas.server.pki.TerminalPermissionAO;
import de.governikus.eumw.utils.key.KeyStoreSupporter;
import de.governikus.eumw.utils.key.SecurityProvider;
import de.governikus.eumw.utils.xml.XmlException;
import de.governikus.eumw.utils.xml.XmlHelper;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;


@Slf4j
@AllArgsConstructor
@Controller
@RequestMapping(ContextPaths.ADMIN_CONTEXT_PATH + ContextPaths.IMPORT_EXPORT_CONFIGURATION)
public class ImportExportConfigurationController
{

  private static final String CONFIGURATION_FORM = "pages" + ContextPaths.IMPORT_EXPORT_CONFIGURATION;

  public static final String ERROR_ATTRIBUTE = "error";

  public static final String MSG_ATTRIBUTE = "msg";

  private final ConfigurationService configurationService;

  private final TerminalPermissionAO facade;


  /**
   * Index Page Show all information and options
   */
  @GetMapping("")
  public String index(Model model, @ModelAttribute String error, @ModelAttribute String msg)
  {
    if (StringUtils.isNotBlank(error))
    {
      model.addAttribute(ERROR_ATTRIBUTE, error);
    }
    if (StringUtils.isNotBlank(msg))
    {
      model.addAttribute(MSG_ATTRIBUTE, msg);
    }
    return CONFIGURATION_FORM;
  }

  /**
   * tries to save the eidas middleware configuration received by the client
   *
   * @param xml the request body received by the client
   */
  @PostMapping("/uploadConfiguration")
  public String saveConfiguration(Model model, @RequestParam("configurationFile") MultipartFile xml)
  {
    if (xml.isEmpty())
    {
      model.addAttribute(ERROR_ATTRIBUTE, "Please provide a file in the upload field");
      return CONFIGURATION_FORM;
    }
    try
    {
      EidasMiddlewareConfig eidasMiddlewareConfig = XmlHelper.unmarshal(new String(xml.getBytes(),
                                                                                   StandardCharsets.UTF_8),
                                                                        EidasMiddlewareConfig.class);
      Optional.ofNullable(eidasMiddlewareConfig.getEidasConfiguration())
              .ifPresent(eidasConfiguration -> eidasConfiguration.setDecryptionKeyPairName(null));

      StringBuilder errors = new StringBuilder("Following errors occurred while importing configuration: <br>");
      boolean anyError = false;

      // Check key stores
      if (eidasMiddlewareConfig.getKeyData() != null && eidasMiddlewareConfig.getKeyData().getKeyStore() != null)
      {
        List<KeyStoreType> keyStoreTypeToRemove = new LinkedList<>();
        for ( KeyStoreType keyStoreType : eidasMiddlewareConfig.getKeyData().getKeyStore() )
        {
          String errorString = checkKeyStore(keyStoreType);
          if (errorString == null)
          {
            continue;
          }
          anyError = true;
          removeKeyPairTypes(eidasMiddlewareConfig, keyStoreType.getName());
          keyStoreTypeToRemove.add(keyStoreType);
          errors.append(errorString);
        }
        eidasMiddlewareConfig.getKeyData().getKeyStore().removeAll(keyStoreTypeToRemove);
      }

      // Check certificates
      if (eidasMiddlewareConfig.getKeyData() != null && eidasMiddlewareConfig.getKeyData().getCertificate() != null)
      {
        List<CertificateType> certificateTypesToRemove = new LinkedList<>();
        for ( CertificateType certificateType : eidasMiddlewareConfig.getKeyData().getCertificate() )
        {
          String msg = checkCertificate(certificateType);
          if (msg != null)
          {
            anyError = true;
            errors.append(msg);
            eraseCertificateFromConfig(eidasMiddlewareConfig, certificateType.getName());
            certificateTypesToRemove.add(certificateType);
          }
        }
        eidasMiddlewareConfig.getKeyData().getCertificate().removeAll(certificateTypesToRemove);
      }

      if (anyError)
      {
        model.addAttribute(ERROR_ATTRIBUTE, errors.toString());
      }
      configurationService.saveConfiguration(eidasMiddlewareConfig, false);
    }
    catch (IOException | XmlException e)
    {
      log.warn("Could not save configuration file", e);
      model.addAttribute(ERROR_ATTRIBUTE, "Could not upload configuration! See logs for more information");
      return CONFIGURATION_FORM;
    }

    model.addAttribute(MSG_ATTRIBUTE, "Configuration successfully imported!");
    CertificationRevocationListImpl.tryInitialize(configurationService, facade);
    return CONFIGURATION_FORM;
  }

  private String checkCertificate(CertificateType certificateType)
  {
    // Check data available
    if (ArrayUtils.isEmpty(certificateType.getCertificate()))
    {
      return String.format("Certificate %s has no data. <br>", certificateType.getName());
    }
    // Parse certificate
    try
    {
      CertificateFactory.getInstance("X509", SecurityProvider.BOUNCY_CASTLE_PROVIDER)
                        .generateCertificate(new ByteArrayInputStream(certificateType.getCertificate()));
    }
    catch (CertificateException e)
    {
      if (log.isDebugEnabled())
      {
        log.debug(String.format("Could not parse certificate %s while config import", certificateType.getName()), e);
      }
      return String.format("Certificte %s could not be parsed: %s", certificateType.getName(), e.getMessage());
    }
    return null;
  }

  private void eraseCertificateFromConfig(EidasMiddlewareConfig eidasMiddlewareConfig, String name)
  {
    eraseCertificateFromEidasConfig(eidasMiddlewareConfig.getEidasConfiguration(), name);
    eraseCertificateFromEidConfig(eidasMiddlewareConfig.getEidConfiguration(), name);
  }

  private void eraseCertificateFromEidConfig(EidasMiddlewareConfig.EidConfiguration eidConfiguration, String name)
  {
    for ( DvcaConfigurationType dvcaConfigurationType : eidConfiguration.getDvcaConfiguration() )
    {
      if (dvcaConfigurationType.getBlackListTrustAnchorCertificateName().equals(name))
      {
        dvcaConfigurationType.setBlackListTrustAnchorCertificateName("");
      }
      if (dvcaConfigurationType.getMasterListTrustAnchorCertificateName().equals(name))
      {
        dvcaConfigurationType.setMasterListTrustAnchorCertificateName("");
      }
      if (dvcaConfigurationType.getServerSSLCertificateName().equals(name))
      {
        dvcaConfigurationType.setServerSSLCertificateName("");
      }

    }
  }

  private void eraseCertificateFromEidasConfig(EidasMiddlewareConfig.EidasConfiguration eidasConfiguration, String name)
  {
    if (eidasConfiguration.getMetadataSignatureVerificationCertificateName().equals(name))
    {
      eidasConfiguration.setMetadataSignatureVerificationCertificateName("");
    }
  }

  private String checkKeyStore(KeyStoreType keyStoreType)
  {
    if (keyStoreType.getName() == null || keyStoreType.getKeyStore() == null || keyStoreType.getType() == null)
    {
      return String.format("Key store %s has missing data. (Name/Type/Bytes) <br>", keyStoreType.getName());
    }

    if (!"JKS".equals(keyStoreType.getType().value()) && !"PKCS12".equals(keyStoreType.getType().value()))
    {
      return String.format("Key store %s has unsupported key store type %s. Must be JKS or PKCS12. <br>",
                           keyStoreType.getName(),
                           keyStoreType.getType());
    }

    try
    {
      KeyStoreSupporter.readKeyStore(keyStoreType.getKeyStore(),
                                     KeyStoreSupporter.KeyStoreType.valueOf(keyStoreType.getType()
                                                                                        .value()
                                                                                        .replace("_", "")),
                                     keyStoreType.getPassword());
    }
    catch (Exception e)
    {
      if (log.isDebugEnabled())
      {
        log.debug("Keystore check failed for keystore " + keyStoreType.getName(), e);
      }
      return String.format("Key store %s could not be read. Wrong password or corrupt key store. <br>",
                           keyStoreType.getName());
    }
    return null;
  }

  private void removeKeyPairTypes(EidasMiddlewareConfig eidasMiddlewareConfig, String invalidKeyStore)
  {
    Set<KeyPairType> referencingKeyPairs = eidasMiddlewareConfig.getKeyData()
                                                                .getKeyPair()
                                                                .parallelStream()
                                                                .filter(c -> invalidKeyStore.equals(c.getKeyStoreName()))
                                                                .collect(Collectors.toSet());
    for ( KeyPairType referencingKeyPair : referencingKeyPairs )
    {
      for ( ServiceProviderType type : eidasMiddlewareConfig.getEidConfiguration().getServiceProvider() )
      {
        if (type.getClientKeyPairName().equals(referencingKeyPair.getName()))
        {
          type.setClientKeyPairName("");
        }
      }

      if (eidasMiddlewareConfig.getEidasConfiguration().getSignatureKeyPairName().equals(referencingKeyPair.getName()))
      {
        eidasMiddlewareConfig.getEidasConfiguration().setSignatureKeyPairName("");
      }
      eidasMiddlewareConfig.getKeyData().getKeyPair().remove(referencingKeyPair);
    }
  }

  /**
   * downloads the eidas middleware configuration without private keys and passwords
   *
   * @return the eidas middleware configuration as xml
   */
  @GetMapping(value = "/downloadWithoutPrivateKeys", produces = MediaType.APPLICATION_OCTET_STREAM_VALUE)
  public Object downloadConfigurationWithoutPrivateKeys(Model model)
  {
    return getConfiguration(model, false);
  }

  /**
   * downloads the eidas middleware configuration with private keys and passwords
   *
   * @return the eidas middleware configuration as xml
   */
  @GetMapping(value = "downloadWithPrivateKeys", produces = MediaType.APPLICATION_OCTET_STREAM_VALUE)
  public Object downloadConfigurationWithPrivateKeys(Model model)
  {
    return getConfiguration(model, true);
  }

  private Object getConfiguration(Model model, boolean withPrivateKeys)
  {
    Optional<EidasMiddlewareConfig> eidasMiddlewareConfig;
    if (withPrivateKeys)
    {
      eidasMiddlewareConfig = configurationService.getConfiguration();
    }
    else
    {
      eidasMiddlewareConfig = configurationService.downloadConfigWithoutKeys();
    }
    if (eidasMiddlewareConfig.isEmpty())
    {
      model.addAttribute(MSG_ATTRIBUTE, "No configuration present!");
      return CONFIGURATION_FORM;
    }
    String configAsString = XmlHelper.marshalObject(eidasMiddlewareConfig.get());
    String configurationFileName = "eIDAS_Middleware_configuration" + (withPrivateKeys ? "_full" : "_noKeys") + ".xml";

    return ResponseEntity.ok()
                         .header("Content-Disposition", "attachment; filename=" + configurationFileName)
                         .contentType(MediaType.APPLICATION_OCTET_STREAM)
                         .body(configAsString.getBytes(StandardCharsets.UTF_8));
  }
}

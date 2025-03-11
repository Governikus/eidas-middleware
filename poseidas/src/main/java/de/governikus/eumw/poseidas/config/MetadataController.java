package de.governikus.eumw.poseidas.config;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import jakarta.validation.Valid;

import org.apache.commons.lang3.StringUtils;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import de.governikus.eumw.config.ConnectorMetadataType;
import de.governikus.eumw.config.EidasMiddlewareConfig;
import de.governikus.eumw.eidascommon.ContextPaths;
import de.governikus.eumw.eidascommon.CryptoAlgUtil;
import de.governikus.eumw.eidasstarterkit.EidasMetadataNode;
import de.governikus.eumw.eidasstarterkit.EidasSaml;
import de.governikus.eumw.poseidas.config.model.MetadataVerificationCertificateModel;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationException;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationService;
import de.governikus.eumw.poseidas.service.MetadataService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;


/**
 * Controller for the metadata administration page.
 */
@Controller
@RequiredArgsConstructor
@Slf4j
@RequestMapping(ContextPaths.ADMIN_CONTEXT_PATH + ContextPaths.METADATA_CONFIG)
public class MetadataController
{

  private static final String NO_METADATA_FILE_WITH_ENTITY_ID_FOUND = "No metadata file with entityID found: ";

  private static final String INDEX_TEMPLATE = "pages/metadata/index";

  private static final String REDIRECT_TO_INDEX = "redirect:" + ContextPaths.ADMIN_CONTEXT_PATH
                                                  + ContextPaths.METADATA_CONFIG;

  private static final String REDIRECT_ATTRIBUTE_ERROR = "error";

  private final ConfigurationService configurationService;

  private final MetadataService metadataService;

  /**
   * Prepare index page.
   *
   * @param model
   * @param error
   * @param msg
   * @return
   */
  @GetMapping
  public String index(Model model, @ModelAttribute String error, @ModelAttribute String msg)
  {
    if (error != null && !error.isBlank())
    {
      model.addAttribute(REDIRECT_ATTRIBUTE_ERROR, error);
    }

    List<EidasMetadataEntry> metadataFiles = getMetadataFiles();
    model.addAttribute("metafiles", metadataFiles);
    List<String> errorMessages = metadataFiles.stream()
                                              .map(EidasMetadataEntry::errorMessage)
                                              .filter(Objects::nonNull)
                                              .toList();
    String appendCurrentMetadataErrorMessage = addInvalidMetadataErrorMessage(errorMessages, error);
    if (!appendCurrentMetadataErrorMessage.isBlank())
    {
      model.addAttribute(REDIRECT_ATTRIBUTE_ERROR, appendCurrentMetadataErrorMessage);
    }
    String metadataSignatureVerificationCertificateName = configurationService.getConfiguration()
                                                                              .map(EidasMiddlewareConfig::getEidasConfiguration)
                                                                              .map(EidasMiddlewareConfig.EidasConfiguration::getMetadataSignatureVerificationCertificateName)
                                                                              .orElse(null);
    if (StringUtils.isNotBlank(metadataSignatureVerificationCertificateName))
    {
      // Ensure Key Size
      try
      {
        configurationService.getSamlCertificate(metadataSignatureVerificationCertificateName);
      }
      catch (ConfigurationException e)
      {
        String errorMessage = error + "The currently selected metadata verification certificate is not valid: "
                              + e.getMessage();

        if (log.isDebugEnabled())
        {
          log.debug(errorMessage, e);
        }
        model.addAttribute(REDIRECT_ATTRIBUTE_ERROR, errorMessage);
      }
    }
    model.addAttribute("metadataVerificationModel",
                       new MetadataVerificationCertificateModel(metadataSignatureVerificationCertificateName));
    return INDEX_TEMPLATE;
  }

  private String addInvalidMetadataErrorMessage(List<String> errorMessages, String error)
  {
    StringBuilder stringBuilder = new StringBuilder(error);
    errorMessages.forEach(s -> stringBuilder.append('\n').append(s));
    return stringBuilder.toString();
  }

  private List<EidasMetadataEntry> getMetadataFiles()
  {
    return configurationService.getConfiguration()
                               .map(EidasMiddlewareConfig::getEidasConfiguration)
                               .map(EidasMiddlewareConfig.EidasConfiguration::getConnectorMetadata)
                               .stream()
                               .flatMap(List::stream)
                               .map(connectorMetadataType -> {
                                 try
                                 {
                                   EidasMetadataNode eidasMetadataNode = parseToEidasMetadata(connectorMetadataType.getValue());
                                   return new EidasMetadataEntry(eidasMetadataNode.getEntityId(),
                                                                 eidasMetadataNode.getCheckedAsValid(), null);
                                 }
                                 catch (Exception e)
                                 {
                                   log.warn("Cannot parse already saved metadata with entityId {}. This metadata is not usable by the middleware and must be deleted or replaced.",
                                            connectorMetadataType.getEntityID(),
                                            e);
                                   String errorMessage = String.format("Cannot parse already saved metadata with entityId %s. This metadata is not usable by the middleware and must be deleted or replaced. See the log of the middleware for more details.",
                                                                       connectorMetadataType.getEntityID());
                                   return new EidasMetadataEntry(connectorMetadataType.getEntityID(), Boolean.FALSE,
                                                                 errorMessage);
                                 }
                               })
                               .sorted(Comparator.comparing(EidasMetadataEntry::entityId))
                               .toList();
  }

  record EidasMetadataEntry(String entityId, Boolean checkedAsValid, String errorMessage) {
  }

  private EidasMetadataNode parseToEidasMetadata(byte[] bytes) throws Exception
  {
    final Optional<String> metadataVerificationCertificateName = configurationService.getConfiguration()
                                                                                     .map(EidasMiddlewareConfig::getEidasConfiguration)
                                                                                     .map(EidasMiddlewareConfig.EidasConfiguration::getMetadataSignatureVerificationCertificateName);

    EntityDescriptor metadata;
    try
    {
      metadata = EidasSaml.unmarshalMetadata(new ByteArrayInputStream(bytes));
    }
    catch (Exception e)
    {
      log.info("Could not parse metadata!", e);
      throw e;
    }

    if (metadata.isSigned())
    {
      try
      {
        CryptoAlgUtil.verifyDigestAndSignatureAlgorithm(metadata.getSignature());
      }
      catch (Exception e)
      {
        log.info("Invalid digest hash algorithm or signature algorithm used for the signature of the metadata", e);
        throw e;
      }
    }

    X509Certificate signatureVerificationCertificate = null;
    if (metadataVerificationCertificateName.isPresent())
    {
      try
      {
        signatureVerificationCertificate = configurationService.getSamlCertificate(metadataVerificationCertificateName.get());
      }
      catch (ConfigurationException e)
      {
        log.warn("Cannot get or use the metadata verification certificate", e);
      }
    }

    try
    {
      return EidasSaml.parseMetaDataNode(new ByteArrayInputStream(bytes), signatureVerificationCertificate, true);
    }
    catch (Exception e)
    {
      log.info("Could not parse metadata!", e);
      throw e;
    }
  }

  private Optional<byte[]> getMetadataFileAsBytes(String entityID)
  {
    return configurationService.getConfiguration()
                               .map(EidasMiddlewareConfig::getEidasConfiguration)
                               .map(EidasMiddlewareConfig.EidasConfiguration::getConnectorMetadata)
                               .stream()
                               .flatMap(List::stream)
                               .filter(d -> entityID.equals(d.getEntityID()))
                               .findAny()
                               .map(ConnectorMetadataType::getValue);
  }

  /**
   * Remove a metadata file from config (first step, will ask for confirmation).
   *
   * @param model
   * @param entityIDUrlEncoded URL encoded entityID of the metadata to be deleted
   * @param redirectAttributes
   * @return redirect
   */
  @GetMapping("/remove")
  public String remove(Model model,
                       @RequestParam(name = "entityID") String entityIDUrlEncoded,
                       RedirectAttributes redirectAttributes)
  {
    String entityID = URLDecoder.decode(entityIDUrlEncoded, StandardCharsets.UTF_8);
    final Optional<byte[]> optionalEidasMetadataBytes = getMetadataFileAsBytes(entityID);
    if (optionalEidasMetadataBytes.isEmpty())
    {
      redirectAttributes.addFlashAttribute(REDIRECT_ATTRIBUTE_ERROR, NO_METADATA_FILE_WITH_ENTITY_ID_FOUND + entityID);
      return REDIRECT_TO_INDEX;
    }
    model.addAttribute("entityId", entityID);
    model.addAttribute("content", new String(optionalEidasMetadataBytes.get()));
    return "pages/metadata/deleteMetadata";
  }

  /**
   * Remove a metadata file from config (second step, call when confirmation has been given).
   *
   * @param entityIDUrlEncoded URL encoded entityID of the metadata to be deleted
   * @param redirectAttributes
   * @return redirect
   */
  @PostMapping("/remove")
  public String removeConfirmed(@RequestParam(name = "entityID") String entityIDUrlEncoded,
                                RedirectAttributes redirectAttributes)
  {
    String entityID = URLDecoder.decode(entityIDUrlEncoded, StandardCharsets.UTF_8);
    final Optional<byte[]> optionalEidasMetadataBytes = getMetadataFileAsBytes(entityID);
    if (optionalEidasMetadataBytes.isEmpty())
    {
      redirectAttributes.addFlashAttribute(REDIRECT_ATTRIBUTE_ERROR, NO_METADATA_FILE_WITH_ENTITY_ID_FOUND + entityID);
      return REDIRECT_TO_INDEX;
    }

    // remove
    final EidasMiddlewareConfig eidasMiddlewareConfig = configurationService.getConfiguration()
                                                                            .orElse(new EidasMiddlewareConfig());
    // always exists, otherwise metadata would not have been found
    final EidasMiddlewareConfig.EidasConfiguration eidasConfiguration = eidasMiddlewareConfig.getEidasConfiguration();
    eidasConfiguration.getConnectorMetadata().removeIf(d -> entityID.equals(d.getEntityID()));
    configurationService.saveConfiguration(eidasMiddlewareConfig, false);

    redirectAttributes.addFlashAttribute("msg", "Metadata file removed: " + entityID);
    return REDIRECT_TO_INDEX;
  }

  /**
   * Download a metadata file.
   *
   * @param entityIDUrlEncoded URL encoded entityID of the metadata to be downloaded
   * @param redirectAttributes
   * @return
   */
  @GetMapping(value = "/download", produces = MediaType.APPLICATION_OCTET_STREAM_VALUE)
  public Object downloadConnectorMetadata(@RequestParam(name = "entityID") String entityIDUrlEncoded,
                                          RedirectAttributes redirectAttributes)
  {
    String entityID = URLDecoder.decode(entityIDUrlEncoded, StandardCharsets.UTF_8);
    final Optional<byte[]> metadataFiles = getMetadataFileAsBytes(entityID);
    if (metadataFiles.isEmpty())
    {
      redirectAttributes.addFlashAttribute(REDIRECT_ATTRIBUTE_ERROR, NO_METADATA_FILE_WITH_ENTITY_ID_FOUND + entityID);
      return REDIRECT_TO_INDEX;
    }

    return ResponseEntity.ok()
                         .header("Content-Disposition", "attachment; filename=Metadata.xml")
                         .contentType(MediaType.APPLICATION_OCTET_STREAM)
                         .body(metadataFiles.get());
  }

  /**
   * Download the metadata of the middleware.
   *
   * @param redirectAttributes
   * @param referer
   * @return
   */
  @GetMapping(value = "/downloadmiddlewaremetadata", produces = MediaType.APPLICATION_OCTET_STREAM_VALUE)
  public Object downloadMiddlewareMetadata(RedirectAttributes redirectAttributes,
                                           @RequestHeader(value = "referer", required = false) String referer)
  {
    byte[] middlewareMetadata = metadataService.getMetadata();
    if (middlewareMetadata.length == 0)
    {
      redirectAttributes.addFlashAttribute(REDIRECT_ATTRIBUTE_ERROR,
                                           "Can not download Metadata. Please check your log and your configuration.");
      String responseTo;
      try
      {
        responseTo = new URI(referer).getPath();
      }
      catch (URISyntaxException e)
      {
        log.warn("Could not resolve incoming download request for middleware metadata.", e);
        return REDIRECT_TO_INDEX;
      }
      return "redirect:" + responseTo;
    }
    return ResponseEntity.ok()
                         .header("Content-Disposition", "attachment; filename=Metadata.xml")
                         .contentType(MediaType.APPLICATION_OCTET_STREAM)
                         .body(middlewareMetadata);
  }

  /**
   * Upload metadata file.
   *
   * @param metadataFile
   * @param redirectAttributes
   * @return
   */
  @PostMapping("/metadata")
  public String uploadMetadata(@RequestParam("metadataFile") MultipartFile metadataFile,
                               RedirectAttributes redirectAttributes)
  {
    final EidasMiddlewareConfig eidasMiddlewareConfig = configurationService.getConfiguration()
                                                                            .orElseGet(EidasMiddlewareConfig::new);
    final EidasMiddlewareConfig.EidasConfiguration eidasConfiguration = Optional.ofNullable(eidasMiddlewareConfig.getEidasConfiguration())
                                                                                .orElse(new EidasMiddlewareConfig.EidasConfiguration());

    try
    {
      // Check if metadata can be parsed!
      final EidasMetadataNode eidasMetadataNode = parseToEidasMetadata(metadataFile.getBytes());
      final String entityId = eidasMetadataNode.getEntityId();
      if (getMetadataFileAsBytes(entityId).isPresent())
      {
        redirectAttributes.addFlashAttribute(REDIRECT_ATTRIBUTE_ERROR,
                                             "There is a metadata file already uploaded with the entityID " + entityId
                                                                       + " !");
        return REDIRECT_TO_INDEX;
      }
      eidasConfiguration.getConnectorMetadata().add(new ConnectorMetadataType(metadataFile.getBytes(), entityId));
    }
    catch (IOException e)
    {
      log.warn("Could not save metadata file", e);
      redirectAttributes.addFlashAttribute("msg", "Could not upload file!");
      return REDIRECT_TO_INDEX;
    }
    catch (Exception e)
    {
      log.warn("Could not save metadata file", e);
      redirectAttributes.addFlashAttribute("msg", e.getMessage());
      return REDIRECT_TO_INDEX;
    }

    eidasMiddlewareConfig.setEidasConfiguration(eidasConfiguration);
    configurationService.saveConfiguration(eidasMiddlewareConfig, false);

    redirectAttributes.addFlashAttribute("msg", "Metadata file uploaded successfully");
    return REDIRECT_TO_INDEX;
  }

  /**
   * Upload metadata verification certificate.
   *
   * @param metadataVerificationCertificateModel
   * @param redirectAttributes
   * @return
   */
  @PostMapping("/metadataSignatureVerificationCertificate")
  public String uploadMetadataVerificationCertificate(@Valid @ModelAttribute MetadataVerificationCertificateModel metadataVerificationCertificateModel,
                                                      RedirectAttributes redirectAttributes)
  {
    // Verify the key size of the verification certificate
    try
    {
      configurationService.getSamlCertificate(metadataVerificationCertificateModel.getMetadataSignatureVerificationCertificateName());
    }
    catch (ConfigurationException e)
    {
      // Exception message already logged in Utils.ensureKeySize
      redirectAttributes.addFlashAttribute(REDIRECT_ATTRIBUTE_ERROR,
                                           "Cannot save the selected metadata verification certificate: "
                                                    + e.getMessage());
      return REDIRECT_TO_INDEX;
    }

    final EidasMiddlewareConfig eidasMiddlewareConfig = configurationService.getConfiguration()
                                                                            .orElseGet(EidasMiddlewareConfig::new);

    final EidasMiddlewareConfig.EidasConfiguration eidasConfiguration = Optional.ofNullable(eidasMiddlewareConfig.getEidasConfiguration())
                                                                                .orElse(new EidasMiddlewareConfig.EidasConfiguration());

    eidasConfiguration.setMetadataSignatureVerificationCertificateName(metadataVerificationCertificateModel.getMetadataSignatureVerificationCertificateName());
    eidasMiddlewareConfig.setEidasConfiguration(eidasConfiguration);
    configurationService.saveConfiguration(eidasMiddlewareConfig, false);

    redirectAttributes.addFlashAttribute("msg", "Metadata signature verification certificate set.");
    return REDIRECT_TO_INDEX;
  }
}

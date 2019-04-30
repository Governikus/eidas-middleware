/*
 * Copyright (c) 2019 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.configuration.wizard.web.controller;

import java.util.List;

import javax.validation.Valid;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.servlet.ModelAndView;

import de.governikus.eumw.configuration.wizard.exceptions.ApplicationPropertiesSaveException;
import de.governikus.eumw.configuration.wizard.exceptions.InvalidNameException;
import de.governikus.eumw.configuration.wizard.exceptions.MiddlewarePropertiesSaveException;
import de.governikus.eumw.configuration.wizard.exceptions.PoseidasConfigSaveException;
import de.governikus.eumw.configuration.wizard.exceptions.SavingFailedException;
import de.governikus.eumw.configuration.wizard.exceptions.WrongAliasException;
import de.governikus.eumw.configuration.wizard.exceptions.WrongPasswordException;
import de.governikus.eumw.configuration.wizard.identifier.HSMTypeIdentifier;
import de.governikus.eumw.configuration.wizard.projectconfig.ConfigDirectory;
import de.governikus.eumw.configuration.wizard.web.controller.validators.FormValidator;
import de.governikus.eumw.configuration.wizard.web.handler.HandlerHolder;
import de.governikus.eumw.configuration.wizard.web.model.CertificateForm;
import de.governikus.eumw.configuration.wizard.web.model.ConfigurationForm;
import de.governikus.eumw.configuration.wizard.web.model.KeystoreForm;
import de.governikus.eumw.configuration.wizard.web.model.poseidasxml.MinimalServiceProviderForm;
import de.governikus.eumw.configuration.wizard.web.model.poseidasxml.ServiceProviderForm;
import de.governikus.eumw.configuration.wizard.web.utils.ExceptionHelper;
import de.governikus.eumw.configuration.wizard.web.utils.WebViews;
import de.governikus.eumw.configuration.wizard.web.utils.WizardPage;
import de.governikus.eumw.utils.key.exceptions.KeyStoreCreationFailedException;
import lombok.extern.slf4j.Slf4j;



/**
 * project: eumw <br>
 * author Pascal Knueppel <br>
 * created at: 07.02.2018 - 14:33 <br>
 * <br>
 */
@Slf4j
@Controller
@RequestMapping("/")
@SessionAttributes({"coreConfiguration", "currentPage"})
public class ConfigurationWizardController
{

  /**
   * Constant string: <code>keystoreFile</code>.
   */
  private static final String KEYSTORE_FILE = "keystoreFile";

  /**
   * this value is an optional value that will tell us whre the configuration should be stored in the end
   */
  @Autowired
  private ConfigDirectory configDirectory;

  /**
   * we give the configuration directory to the view in order to assure that the directory where the
   * configuration is stored can be displayed for the user
   */
  @ModelAttribute("configDirectory")
  public ConfigDirectory getConfigDirectory()
  {
    return configDirectory;
  }

  /**
   * this form will describe the configuration form that holds all parameters that are configurable and will
   * make them available for the html view
   */
  @ModelAttribute("coreConfiguration")
  public ConfigurationForm getConfigurationForm()
  {
    ConfigurationForm configurationForm = new ConfigurationForm();
    configurationForm.setConfigDirectory(configDirectory);
    return configurationForm;
  }

  /**
   * will add a certificate form for certificate uploading to the html view
   */
  @ModelAttribute("certificateForm")
  public CertificateForm getCertificateForm()
  {
    return new CertificateForm();
  }

  /**
   * will add the list of all uploaded certificates to the view
   */
  @ModelAttribute("certificateList")
  public List<CertificateForm> getAllCertificates()
  {
    return HandlerHolder.getCertificateHandler().getAll();
  }

  /**
   * will add the list of all uploaded keystores to the view
   */
  @ModelAttribute("keystoreList")
  public List<KeystoreForm> getAllKeystores()
  {
    return HandlerHolder.getKeystoreHandler().getAll();
  }

  /**
   * will add a keystore form for keystore uploading to the html view
   */
  @ModelAttribute("keystoreForm")
  public KeystoreForm getKeystoreForm()
  {
    return new KeystoreForm();
  }

  /**
   * adds the current view parameter to the html view. First value is application.properties page
   */
  @ModelAttribute("currentPage")
  public WizardPage getCurrentView(@ModelAttribute("coreConfiguration") ConfigurationForm configurationForm)
  {
    if (StringUtils.isNotBlank(configDirectory.getConfigDirectory())
        && configurationForm.isConfigurationLoaded())
    {
      return WizardPage.APPLICATION_PROPERTIES_VIEW;
    }
    else if (StringUtils.isBlank(configDirectory.getConfigDirectory()))
    {
      return WizardPage.BASE_PATH_VIEW;
    }
    else
    {
      return WizardPage.UPLOAD_CONFIG_PROPERTIES_VIEW;
    }
  }

  /**
   * load view: the config-wizard.html
   */
  @GetMapping
  public ModelAndView loadConfigurationView()
  {
    return new ModelAndView(WebViews.CONFIG_WIZARD);
  }

  /**
   * will load the next page or the current page in case of an validation error
   */
  @PostMapping(params = {"page=next"})
  public ModelAndView loadNextPageOnWizard(@Valid @ModelAttribute("coreConfiguration") ConfigurationForm configurationForm,
                                           BindingResult bindingResult,
                                           @ModelAttribute("currentPage") WizardPage currentPage)
  {
    ModelAndView modelAndView = new ModelAndView(WebViews.CONFIG_WIZARD);
    FormValidator.validateView(currentPage, configurationForm, bindingResult);
    if (bindingResult.hasErrors())
    {
      return modelAndView;
    }
    modelAndView.addObject("currentPage", currentPage.getNextPage());
    return modelAndView;
  }

  /**
   * will load the previous page
   *
   * @param currentPage is added as parameter in order to maintain the value in the request
   */
  @PostMapping(params = {"page=previous"})
  public ModelAndView loadPreviousPageOnWizard(@ModelAttribute("coreConfiguration") ConfigurationForm configurationForm,
                                               @ModelAttribute("currentPage") WizardPage currentPage)
  {
    ModelAndView modelAndView = new ModelAndView(WebViews.CONFIG_WIZARD);
    modelAndView.addObject("currentPage", currentPage.getPreviousPage());
    return modelAndView;
  }

  /**
   * will save the configuration if there are no validation errors.
   */
  @PostMapping(params = {"action=save"})
  public ModelAndView saveConfigurationButton(@Valid @ModelAttribute("coreConfiguration") ConfigurationForm configurationForm,
                                              BindingResult bindingResult,
                                              @ModelAttribute("currentPage") WizardPage currentPage)
  {
    FormValidator.validateView(currentPage, configurationForm, bindingResult);
    if (bindingResult.hasErrors())
    {
      return new ModelAndView(WebViews.CONFIG_WIZARD);
    }

    ModelAndView modelAndView = new ModelAndView(WebViews.SAVE_SUCCESS);
    try
    {
      configurationForm.saveConfiguration();
      modelAndView.addObject("saveLocation", configurationForm.getSaveLocation());
    }
    catch (PoseidasConfigSaveException | MiddlewarePropertiesSaveException
      | ApplicationPropertiesSaveException ex)
    {
      log.error(ex.getMessage(), ex);
      modelAndView.addObject(ex.getMessage(), ExceptionHelper.getRootMessage(ex));
    }
    catch (SavingFailedException ex)
    {
      log.error(ex.getMessage(), ex);
      modelAndView.addObject("saving_failed", ExceptionHelper.getRootMessage(ex));
    }
    modelAndView.addObject("save_location", configurationForm.getSaveLocation());
    return modelAndView;
  }

  /**
   * this method accepts a certificate that will be uploaded for selection fields
   *
   * @param certificateForm the certificate form that contains the uploaded file
   * @return current view
   */
  @PostMapping(params = {"upload=certificate"})
  public ModelAndView uploadCertificateFile(@Valid @ModelAttribute("certificateForm") CertificateForm certificateForm,
                                            BindingResult bindingResult,
                                            @ModelAttribute("coreConfiguration") ConfigurationForm configurationForm)
  {
    ModelAndView modelAndView = new ModelAndView(WebViews.CONFIG_WIZARD);
    if (certificateForm.getCertificateFile() == null || certificateForm.getCertificateFile().getSize() == 0)
    {
      bindingResult.rejectValue("certificateFile",
                                "wizard.status.validation.upload.file",
                                "File must not be empty.");
    }
    try
    {
      certificateForm.getCertificate();
    }
    catch (Exception ex)
    {
      log.error(ex.getMessage(), ex);
      bindingResult.rejectValue("certificateFile", null, ex.getMessage());
    }
    if (bindingResult.hasErrors())
    {
      return modelAndView;
    }
    try
    {
      HandlerHolder.getCertificateHandler().add(certificateForm);
      modelAndView.addObject("certificateUploadSuccess", true);
      modelAndView.addObject("certificateForm", getCertificateForm());
    }
    catch (InvalidNameException ex)
    {
      log.error(ex.getMessage(), ex);
      bindingResult.rejectValue("certificateName", null, ex.getMessage());
    }
    return modelAndView;
  }

  /**
   * this method accepts a keystore that will be uploaded for selection fields
   *
   * @param keystoreForm the keystore form that contains the uploaded file
   * @return current view
   */
  @PostMapping(params = {"upload=keystore"})
  public ModelAndView uploadKeystoreFile(@Valid @ModelAttribute("keystoreForm") KeystoreForm keystoreForm,
                                         BindingResult bindingResult,
                                         @ModelAttribute("coreConfiguration") ConfigurationForm configurationForm)
  {
    ModelAndView modelAndView = new ModelAndView(WebViews.CONFIG_WIZARD);
    if (keystoreForm.getKeystoreFile() == null || keystoreForm.getKeystoreFile().getSize() == 0)
    {
      bindingResult.rejectValue(KEYSTORE_FILE,
                                "wizard.status.validation.upload.file",
                                "File must not be empty.");
    }
    if (bindingResult.hasErrors())
    {
      return modelAndView;
    }
    try
    {
      keystoreForm.initializeKeystore();
      HandlerHolder.getKeystoreHandler().add(keystoreForm);
      modelAndView.addObject("keystoreUploadSuccess", true);
      modelAndView.addObject("keystoreForm", getKeystoreForm());
    }
    catch (InvalidNameException ex)
    {
      log.error(ex.getMessage(), ex);
      bindingResult.rejectValue("keystoreName", null, ex.getMessage());
    }
    catch (WrongPasswordException ex)
    {
      log.error(ex.getMessage(), ex);
      String errorField = "keystorePassword";
      if (ex.getMessage().contains("private key"))
      {
        errorField = "privateKeyPassword";
      }
      bindingResult.rejectValue(errorField, null, ex.getMessage());
    }
    catch (KeyStoreCreationFailedException ex)
    {
      log.error(ex.getMessage(), ex);
      bindingResult.rejectValue(KEYSTORE_FILE, null, ex.getMessage());
    }
    catch (WrongAliasException ex)
    {
      log.error("could not find given alias within keystore", ex);
      bindingResult.rejectValue(KEYSTORE_FILE, null, ex.getMessage());
    }
    return modelAndView;
  }

  /**
   * this method accepts a minimal service provider that will be added to the list of service providers
   *
   * @return current view
   */
  @PostMapping(params = {"upload=serviceProvider"})
  public ModelAndView uploadServiceProvider(@ModelAttribute("coreConfiguration") ConfigurationForm configurationForm,
                                            BindingResult bindingResult)
  {
    log.debug("Creating new service provider");
    MinimalServiceProviderForm minimalServiceProviderForm = configurationForm.getPoseidasConfig()
                                                                             .getMinimalServiceProviderForm();
    if (StringUtils.isBlank(minimalServiceProviderForm.getEntityID()))
    {
      bindingResult.rejectValue("poseidasConfig.minimalServiceProviderForm.entityID",
                                "wizard.status.validation.blank",
                                "Enter the service provider name");
      return new ModelAndView(WebViews.CONFIG_WIZARD);
    }

    if (minimalServiceProviderForm.getSslKeysForm().getClientKeyForm() == null
        && !HSMTypeIdentifier.isUsingHSM(configurationForm.getApplicationProperties().getHsmType()))
    {
      bindingResult.rejectValue("poseidasConfig.minimalServiceProviderForm.sslKeysForm.clientKeyForm",
                                "wizard.status.validation.keystore",
                                "Choose a keystore.");
      return new ModelAndView(WebViews.CONFIG_WIZARD);
    }

    // Create a new service provider based on the data from the web interface and the common service provider
    // data
    ServiceProviderForm newServiceProvider = new ServiceProviderForm();
    newServiceProvider.setEntityID(minimalServiceProviderForm.getEntityID());

    if (!HSMTypeIdentifier.isUsingHSM(configurationForm.getApplicationProperties().getHsmType()))
    {
      newServiceProvider.getSslKeysForm()
                        .setClientKeyForm(minimalServiceProviderForm.getSslKeysForm().getClientKeyForm());
    }

    newServiceProvider.setPublicServiceProvider(minimalServiceProviderForm.isPublicServiceProvider());
    newServiceProvider.setBlackListTrustAnchor(configurationForm.getPoseidasConfig()
                                                                .getCommonServiceProviderData()
                                                                .getBlackListTrustAnchor());
    newServiceProvider.setMasterListTrustAnchor(configurationForm.getPoseidasConfig()
                                                                 .getCommonServiceProviderData()
                                                                 .getMasterListTrustAnchor());
    newServiceProvider.setDefectListTrustAnchor(configurationForm.getPoseidasConfig()
                                                                 .getCommonServiceProviderData()
                                                                 .getDefectListTrustAnchor());
    newServiceProvider.getSslKeysForm()
                      .setServerCertificate(configurationForm.getPoseidasConfig()
                                                             .getCommonServiceProviderData()
                                                             .getSslKeysForm()
                                                             .getServerCertificate());
    newServiceProvider.setPolicyID(configurationForm.getPoseidasConfig()
                                                    .getCommonServiceProviderData()
                                                    .getPolicyID());

    configurationForm.getPoseidasConfig().getServiceProviders().add(newServiceProvider);

    // clear the fields on the web interface
    configurationForm.getPoseidasConfig().setMinimalServiceProviderForm(new MinimalServiceProviderForm());

    return new ModelAndView(WebViews.CONFIG_WIZARD);
  }

  /**
   * this method deletes the service provider with the given entityID from the list of the service providers
   *
   * @param serviceProviderName The entityID of the service provider to be deleted
   * @return current view
   */
  @PostMapping(params = {"deleteServiceProvider"})
  public ModelAndView deleteServiceProvider(@RequestParam("deleteServiceProvider") String serviceProviderName,
                                            @ModelAttribute("coreConfiguration") ConfigurationForm configurationForm)
  {
    log.debug("Deleting service provider {}", serviceProviderName);
    configurationForm.getPoseidasConfig()
                     .getServiceProviders()
                     .removeIf(serviceProviderForm -> serviceProviderForm.getEntityID()
                                                                         .equals(serviceProviderName));

    return new ModelAndView(WebViews.CONFIG_WIZARD);
  }

  /**
   * This method is called when the upload button for metadata files is clicked
   *
   * @return current view
   */
  @PostMapping(params = "uploadMetadata")
  public ModelAndView uploadMetadata(@ModelAttribute("coreConfiguration") ConfigurationForm configurationForm)
  {
    // nothing to do, business logic is done in EidasMiddlewarePropertiesForm#setUploadedFile
    return new ModelAndView(WebViews.CONFIG_WIZARD);
  }

  /**
   * this method deletes the metadata with the given name from the list of the metadata files
   *
   * @param metadataName The filename of the metadata file to be deleted
   * @return current view
   */
  @PostMapping(params = "deleteMetadata")
  public ModelAndView deleteMetadata(@RequestParam("deleteMetadata") String metadataName,
                                     @ModelAttribute("coreConfiguration") ConfigurationForm configurationForm)
  {
    configurationForm.getEidasmiddlewareProperties()
                     .getServiceProviderMetadataFiles()
                     .entrySet()
                     .removeIf(entry -> entry.getKey().equals(metadataName));
    return new ModelAndView(WebViews.CONFIG_WIZARD);
  }
}

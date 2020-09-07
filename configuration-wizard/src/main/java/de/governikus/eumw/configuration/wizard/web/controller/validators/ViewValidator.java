/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.configuration.wizard.web.controller.validators;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.validation.BindingResult;
import org.springframework.web.multipart.MultipartFile;

import de.governikus.eumw.configuration.wizard.web.handler.NamedObject;
import de.governikus.eumw.configuration.wizard.web.model.ConfigurationForm;
import de.governikus.eumw.configuration.wizard.web.model.poseidasxml.DvcaProvider;
import de.governikus.eumw.utils.xml.XmlHelper;
import lombok.extern.slf4j.Slf4j;


/**
 * project: eumw <br>
 * author Pascal Knueppel <br>
 * created at: 15.02.2018 - 08:30 <br>
 * <br>
 * this functional interface is used to add validation implementations to {@link FormValidator#validateView}
 */
@Slf4j
public abstract class ViewValidator
{

  /**
   * default message for invalid entries to fields
   */
  private static final String DEFAULT_MESSAGE_INVALID = "field entry is not valid";

  /**
   * message key to the validation message if a field entry is empty
   */
  private static final String KEY_VALIDATE_BLANK = "wizard.status.validation.blank";

  /**
   * message key to the validation message if a field entry is not anumber
   */
  private static final String KEY_INVALIDE_NUMBER = "wizard.status.validation.number";

  /**
   * validate a specific part of the configuration form
   *
   * @param configurationForm the configuration form to be validated
   * @param bindingResult the spring validation context object to add the errors directly
   */
  public abstract void validateView(ConfigurationForm configurationForm, BindingResult bindingResult);

  /**
   * will check any string if it is not blank and if it is a bare number
   *
   * @param fieldName the name of the field that resembles the name in the html-view-component
   * @param fieldValue the value of the field
   */
  protected void checkPort(String fieldName, String fieldValue, BindingResult bindingResult)
  {
    if (StringUtils.isBlank(fieldValue))
    {
      bindingResult.rejectValue(fieldName, KEY_VALIDATE_BLANK, DEFAULT_MESSAGE_INVALID);
    }
    else if (!fieldValue.matches("\\d+"))
    {
      bindingResult.rejectValue(fieldName, KEY_INVALIDE_NUMBER, DEFAULT_MESSAGE_INVALID);
    }
  }

  /**
   * will check any string if it is not blank
   *
   * @param fieldName the name of the field that resembles the name in the html-view-component
   * @param fieldValue the value of the field
   */
  protected void checkNonBlankString(String fieldName, String fieldValue, BindingResult bindingResult)
  {
    if (StringUtils.isBlank(fieldValue))
    {
      bindingResult.rejectValue(fieldName, KEY_VALIDATE_BLANK, DEFAULT_MESSAGE_INVALID);
    }
  }

  protected void checkFieldIsInt(String fieldName, String fieldValue, BindingResult bindingResult)
  {
    if (StringUtils.isNotEmpty(fieldValue) && !StringUtils.isNumeric(fieldValue))
      {
      bindingResult.rejectValue(fieldName, KEY_INVALIDE_NUMBER, DEFAULT_MESSAGE_INVALID);
      }
  }

  /**
   * will check any string if it is not blank and if it is an url
   *
   * @param fieldName the name of the field that resembles the name in the html-view-component
   * @param fieldValue the value of the field
   */
  protected void checkUrl(String fieldName, String fieldValue, BindingResult bindingResult)
  {
    if (StringUtils.isBlank(fieldValue))
    {
      bindingResult.rejectValue(fieldName, KEY_VALIDATE_BLANK, DEFAULT_MESSAGE_INVALID);
    }
    else
    {
      try
      {
        new URL(fieldValue);
      }
      catch (MalformedURLException e)
      {
        bindingResult.rejectValue(fieldName, "wizard.status.validation.url", DEFAULT_MESSAGE_INVALID);
      }
    }
  }

  /**
   * will check if keystores or certificates are selected
   *
   * @param fieldName the name of the field that resembles the name in the html-view-component
   * @param fieldValue the value of the field
   * @param isCertificate true if fieldValue is a certificate, otherwise a keystore is expected
   */
  protected void checkNamedObject(String fieldName,
                                  NamedObject fieldValue,
                                  BindingResult bindingResult,
                                  boolean isCertificate)
  {
    if (fieldValue == null || StringUtils.isBlank(fieldValue.getName()))
    {
      if (isCertificate)
      {
        bindingResult.rejectValue(fieldName, "wizard.status.validation.certificate", "Choose a certificate");
      }
      else
      {
        bindingResult.rejectValue(fieldName, "wizard.status.validation.keystore", "Choose a keystore.");
      }
    }
  }

  /**
   * checks if a multipartfile is an empty file
   *
   * @param fieldName the name of the field in the view
   * @param multipartFile the file that should be checked
   */
  protected void checkMultipartFile(String fieldName,
                                    MultipartFile multipartFile,
                                    BindingResult bindingResult)
  {
    if (multipartFile == null || multipartFile.getSize() == 0)
    {
      bindingResult.rejectValue(fieldName, "wizard.status.validation.file.empty", "Upload a file.");
    }
  }

  /**
   * tries to get the content of a file if content is present and will add an error to the binding-result if
   * the content could not be read
   *
   * @param fieldName the name of the field regarding the multipart-file
   * @param multipartFile the file that should hold some content or is empty
   * @param bindingResult the binding result to give errors to the user on the view
   * @return an empty if the content could not be read or the content of the file
   */
  protected Optional<String> getFileContent(String fieldName,
                                            MultipartFile multipartFile,
                                            BindingResult bindingResult)
  {
    if (multipartFile == null || multipartFile.getSize() == 0)
    {
      // everythings fine if no configuration was uploaded the user will type it in him-/herself
      return Optional.empty();
    }
    try
    {
      return Optional.of(IOUtils.toString(multipartFile.getBytes(), StandardCharsets.UTF_8.name()));
    }
    catch (IOException e)
    {
      log.error("could not read uploaded XML file...", e);
      bindingResult.rejectValue(fieldName,
                                "wizard.status.validation.upload.file.unreadable",
                                "Could not read file");
      return Optional.empty();
    }
  }

  /**
   * will check if the given file is a XML file
   *
   * @param fieldName the fieldname of the object within the view
   * @param multipartFile the uploaded file
   * @param bindingResult the binding result to display errors within the view
   * @return the content of the file since it has already been read here
   */
  protected Optional<String> checkXmlFile(String fieldName,
                                          MultipartFile multipartFile,
                                          BindingResult bindingResult)
  {
    String[] content = new String[1];
    getFileContent(fieldName, multipartFile, bindingResult).ifPresent(fileContent -> {
      if (XmlHelper.isXmlWellFormed(fileContent))
      {
        content[0] = fileContent;
      }
      else
      {
        bindingResult.rejectValue(fieldName,
                                  "wizard.status.validation.upload.file.not.xml",
                                  "File is not xml.");
      }
    });
    return Optional.ofNullable(content[0]);
  }

  /**
   * Check that a radio button for the policy is selected.
   *
   * @param fieldName the name of the field in the view
   * @param policyID the policyId that should be checked
   */
  protected void checkRadioButton(String fieldName,
                                  DvcaProvider policyID,
                                  BindingResult bindingResult)
  {
    if (policyID == null)
    {
      bindingResult.rejectValue(fieldName, "wizard.status.validation.dvca.missing", "Choose a dvca policy.");
    }
  }

  /**
   * checks if a Multipartfile contains valid XML content
   *
   * @param fieldname the fieldname to bind error messages to the view
   * @param content the file to check for xml content
   * @param bindingResult to bind the error messages to the view
   */
  protected void checkForXmlContent(String fieldname, byte[] content, BindingResult bindingResult)
  {
    if (content == null || content.length == 0)
    {
      return;
    }
    try
    {
      if (!XmlHelper.isXmlWellFormed(new String(content, StandardCharsets.UTF_8.name())))
      {
        bindingResult.rejectValue(fieldname,
                                  "wizard.status.validation.upload.file.xml.invalid",
                                  new Object[]{fieldname},
                                  "Invalid xml.");
      }
    }
    catch (UnsupportedEncodingException ex)
    {
      bindingResult.rejectValue(fieldname,
                                "wizard.status.validation.upload.file.not.xml",
                                "File is not xml.");
    }
  }
}

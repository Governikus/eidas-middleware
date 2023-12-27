/*
 * Copyright (c) 2022 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.config.base;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Arrays;
import java.util.Optional;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import jakarta.annotation.PostConstruct;

import org.apache.commons.io.FileUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;

import com.gargoylesoftware.htmlunit.Page;
import com.gargoylesoftware.htmlunit.ScriptException;
import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.html.DomElement;
import com.gargoylesoftware.htmlunit.html.HtmlAnchor;
import com.gargoylesoftware.htmlunit.html.HtmlButton;
import com.gargoylesoftware.htmlunit.html.HtmlCheckBoxInput;
import com.gargoylesoftware.htmlunit.html.HtmlFileInput;
import com.gargoylesoftware.htmlunit.html.HtmlNumberInput;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import com.gargoylesoftware.htmlunit.html.HtmlPasswordInput;
import com.gargoylesoftware.htmlunit.html.HtmlSelect;
import com.gargoylesoftware.htmlunit.html.HtmlTextArea;
import com.gargoylesoftware.htmlunit.html.HtmlTextInput;
import com.gargoylesoftware.htmlunit.javascript.JavaScriptErrorListener;

import de.governikus.eumw.config.KeyStoreTypeType;
import de.governikus.eumw.poseidas.service.PasswordHandler;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;


/**
 * Abstract Base Class for frontend tests
 */
@Slf4j
public class WebAdminTestBase
{

  protected static final String PASSWORD = "123456";

  private static final String HASHED_PASSWORD = "$2a$12$J37AIcLQBQA0nuGzbIerIe/aiyMcwQzErtZH27BINUVnQ6TfVUj4y";

  protected static final File TEST_CERTIFICATE_FILE = new File(WebAdminTestBase.class.getResource("/configuration/jks-keystore.cer")
                                                                                     .getPath());

  protected static final File TEST_KEY_STORE_FILE = new File(WebAdminTestBase.class.getResource("/configuration/keystore.jks")
                                                                                   .getPath());

  protected static final File TEST_KEY_STORE_FILE_PKCS12 = new File(WebAdminTestBase.class.getResource("/configuration/keystore.p12")
                                                                                          .getPath());

  protected static final KeyStoreTypeType TEST_KEY_STORE_CONFIG_TYPE = KeyStoreTypeType.JKS;

  protected static final String TEST_CERTIFICATE_ALIAS = "jks-keystore";

  protected static final String TEST_CERTIFICATE_ALIAS_PKCS12 = "pkcs12-keystore";

  @Autowired
  ResourceLoader resourceLoader;

  @Value("${server.ssl.key-store}")
  String serverSSLKeystoreFile;

  @Value("${server.ssl.key-store-password}")
  String serverSSLKeystorePassword;

  /**
   * if spring boot test uses a random port the port will be injected into this variable
   */
  @Getter
  @Value("${local.server.port:8080}")
  private int localServerPort;

  /**
   * contains the URL to which the requests must be sent
   */
  private String defaultUrl;

  /**
   * will be used to execute requests with the application
   */
  @Getter
  private WebClient webClient;

  /**
   * Mock the PasswordHandler so that not password.properties files must be written
   */
  @MockBean
  PasswordHandler passwordHandler;

  @PostConstruct
  public void preparePasswordHandler()
  {
    Mockito.when(passwordHandler.getHashedPassword()).thenReturn(HASHED_PASSWORD);
    Mockito.when(passwordHandler.isPasswordSet()).thenReturn(true);
  }

  /**
   * will initialize the url under which the locally started tomcat can be reached
   */
  @BeforeEach
  public void initializeUrl()
  {
    defaultUrl = "https://localhost:" + localServerPort + "/" + "admin-interface";
  }

  /**
   * this method will create a request url with the given path
   *
   * @param path the context path to the method that should be used
   * @return the complete server-url with the given context path to the method that should be used
   */
  protected String getRequestUrl(String path)
  {
    return defaultUrl + (path.startsWith("/") ? path : "/" + path);
  }

  /**
   * will initialize the {@link #webClient}
   */
  @BeforeEach
  public void initWebClient() throws IOException
  {
    webClient = new WebClient();
    webClient.getOptions().setThrowExceptionOnScriptError(false);
    webClient.getOptions().setCssEnabled(false);
    webClient.getOptions().setThrowExceptionOnFailingStatusCode(false);
    webClient.setJavaScriptErrorListener(new JavaScriptErrorListener()
    {

      @Override
      public void scriptException(HtmlPage htmlPage, ScriptException e)
      {
        // NOOP
      }

      @Override
      public void timeoutError(HtmlPage htmlPage, long l, long l1)
      {
        // NOOP
      }

      @Override
      public void malformedScriptURL(HtmlPage htmlPage, String s, MalformedURLException e)
      {
        // NOOP
      }

      @Override
      public void loadScriptError(HtmlPage htmlPage, URL url, Exception e)
      {
        // NOOP
      }

      @Override
      public void warn(String s, String s1, int i, String s2, int i1)
      {
        // NOOP
      }
    });

    final Resource resource = resourceLoader.getResource(serverSSLKeystoreFile);
    webClient.getOptions().setSSLTrustStore(resource.getURL(), serverSSLKeystorePassword, "JKS");
  }

  /**
   * will assure that the {@link #webClient} will be closed after each test
   */
  @AfterEach
  public void destroyWebClient()
  {
    if (webClient != null)
    {
      webClient.close();
    }
  }

  /**
   * Login at the spring security login form
   *
   * @param loginPage login page
   * @return login page after submit
   * @throws IOException
   */
  protected HtmlPage login(HtmlPage loginPage) throws IOException
  {
    setPasswordValue(loginPage, "password", PASSWORD);
    return submitAnyForm(loginPage);
  }

  protected HtmlPage submitAnyForm(HtmlPage currentPage) throws IOException
  {
    final Optional<HtmlButton> optionalHtmlButton = currentPage.getElementsByTagName("button")
                                                               .stream()
                                                               .map(HtmlButton.class::cast)
                                                               .filter(b -> "submit".equals(b.getAttribute("type")))
                                                               .findFirst();
    if (optionalHtmlButton.isPresent())
    {
      return optionalHtmlButton.get().click();
    }
    return currentPage;
  }

  protected HtmlPage submitFormById(HtmlPage currentPage, String formID) throws IOException
  {
    final DomElement htmlForm = currentPage.getElementById(formID);
    assertNotNull(htmlForm, "Html form with id " + formID + " not found");

    Optional<HtmlButton> optionalSubmitButton = new HtmlPageSearch<HtmlButton>().searchFirstInTree(htmlForm,
                                                                                                   e -> "submit".equalsIgnoreCase(e.getAttribute("type")),
                                                                                                   HtmlButton.class);

    assertTrue(optionalSubmitButton.isPresent(), "No submit button in form " + formID + " found");

    return optionalSubmitButton.get().click();
  }

  /**
   * Assert that a certain message is displayed in the correct field
   *
   * @param currentPage The current HTML page
   * @param inputFieldId to specify the correct input field
   * @param expected expected message
   */
  protected void assertValidationMessagePresent(HtmlPage currentPage, String inputFieldId, String... expected)
  {
    DomElement element = currentPage.getElementById(inputFieldId);
    assertNotNull(element, "field " + inputFieldId + " should not be null.");

    final DomElement nextElementSibling = element.getNextElementSibling();
    assertNotNull(nextElementSibling, "next subling of field " + inputFieldId + " should not be null.");
    assertTrue(nextElementSibling.getAttribute("class").contains("text-danger"),
               "next subling of field " + inputFieldId + " is not a error message.");

    assertTrue(Arrays.stream(expected).anyMatch(e -> nextElementSibling.getTextContent().contains(e)),
               String.format("Error text of %s should contain %s but was '%s'.",
                             inputFieldId,
                             Arrays.stream(expected)
                                   .map(s -> String.format("'%s'", s))
                                   .collect(Collectors.joining(" or ")),
                             nextElementSibling.getTextContent()));

  }

  /**
   * Click a button
   *
   * @param currentPage The current HTML page
   * @param elementId The element ID of the button to be clicked
   */
  protected Page click(HtmlPage currentPage, String elementId) throws IOException
  {
    HtmlButton button = (HtmlButton)currentPage.getElementById(elementId);
    return button.click();
  }


  /**
   * Set a text value
   *
   * @param currentPage The current HTML page
   * @param fieldId to identify the field where the text is set
   * @param text value
   */
  protected void setTextValue(HtmlPage currentPage, String fieldId, String text)
  {
    if (currentPage.getElementById(fieldId) instanceof HtmlTextInput)
    {
      HtmlTextInput textInput = (HtmlTextInput)currentPage.getElementById(fieldId);
      textInput.setText(text);
    }
    else if (currentPage.getElementById(fieldId) instanceof HtmlTextArea)
    {
      HtmlTextArea textArea = (HtmlTextArea)currentPage.getElementById(fieldId);
      textArea.setText(text);
    }
    else
    {
      fail("Cannot set text value for field with id " + fieldId + " and class "
           + currentPage.getElementById(fieldId).getClass().getName());
    }
  }

  /**
   * Set a number value
   *
   * @param currentPage The current HTML page
   * @param fieldId to identify the field where the text is set
   * @param value value
   */
  protected void setNumberValue(HtmlPage currentPage, String fieldId, int value)
  {
    if (currentPage.getElementById(fieldId) instanceof HtmlNumberInput)
    {
      HtmlNumberInput numberInput = (HtmlNumberInput)currentPage.getElementById(fieldId);
      numberInput.setText(Integer.toString(value));
      numberInput.setValueAttribute(Integer.toString(value));
    }
    else
    {
      fail("Cannot set text value for field with id " + fieldId + " and class "
           + currentPage.getElementById(fieldId).getClass().getName());
    }
  }

  /**
   * Set a password value
   *
   * @param currentPage The current HTML page
   * @param fieldId to identify the field where the password is set
   * @param text password value
   */
  protected void setPasswordValue(HtmlPage currentPage, String fieldId, String text)
  {
    HtmlPasswordInput passwordInput = (HtmlPasswordInput)currentPage.getElementById(fieldId);
    passwordInput.setText(text);
  }

  /**
   * Select a value to set a certificate or key store
   *
   * @param currentPage The current HTML page
   * @param fieldId certificate or key store field id
   * @param value value to be selected
   */
  protected void setSelectValue(HtmlPage currentPage, String fieldId, String value)
  {
    HtmlSelect select = (HtmlSelect)currentPage.getElementById(fieldId);
    select.getOptionByValue(value).setSelected(true);
  }

  /**
   * Set the checkbox to the given state
   *
   * @param currentPage The current HTML page
   * @param elementID The element ID of the checkbox to be clicked
   * @param selectCheckbox The state for the checkbox
   */
  protected void setCheckboxValue(HtmlPage currentPage, String elementID, boolean selectCheckbox)
  {
    HtmlCheckBoxInput publicServiceProvider = (HtmlCheckBoxInput)currentPage.getElementById(elementID);
    publicServiceProvider.setChecked(selectCheckbox);
  }


  /**
   * Set files to upload in a file input field
   *
   * @param currentPage The current HTML page
   * @param inputFieldId The element ID of the file upload to be filled
   * @param certificate The file(s) to upload
   */
  protected void setFileUpload(HtmlPage currentPage, String inputFieldId, File... certificate)
  {
    HtmlFileInput certificateFileInput = (HtmlFileInput)currentPage.getElementById(inputFieldId);
    certificateFileInput.setFiles(certificate);
  }

  /**
   * Assertion for presence of {@link Optional}
   *
   * @param optional any optional
   * @param errorMessage message to display of optional is empty
   */
  protected void assertOptionalIsPresent(Optional optional, String errorMessage)
  {
    assertTrue(optional.isPresent(), errorMessage);
  }

  /**
   * Find a {@link HtmlAnchor} by a predicate
   *
   * @param htmlPage page containing the html anchor
   * @param predicate predicate to identify the html anchor
   * @return {@link Optional} of html anchor if found or empty {@link Optional} if not
   */
  protected Optional<HtmlAnchor> getHtmlAnchorByPredicate(HtmlPage htmlPage, Predicate<HtmlAnchor> predicate)
  {
    return htmlPage.getElementsByTagName("a")
                   .parallelStream()
                   .map(HtmlAnchor.class::cast)
                   .filter(predicate)
                   .findFirst();
  }

  protected byte[] getTestCertificate() throws IOException
  {
    return FileUtils.readFileToByteArray(TEST_CERTIFICATE_FILE);
  }

  protected byte[] getTestKeyStoreBytes() throws IOException
  {
    return FileUtils.readFileToByteArray(TEST_KEY_STORE_FILE);
  }

  private void assertAlert(HtmlPage keyManagementPage, String[] expectedMessages, String alertMSG)
  {
    assertNotNull(keyManagementPage.getElementById(alertMSG));
    for ( String message : expectedMessages )
    {
      String alertMessage = keyManagementPage.getHtmlElementById(alertMSG).getTextContent();
      assertTrue(alertMessage.contains(message),
                 String.format("The expected message '%s' was not found in %s", message, alertMessage));
    }
  }

  public void assertMessageAlert(HtmlPage keyManagementPage, String... expectedMessage)
  {
    assertAlert(keyManagementPage, expectedMessage, "alertMSG");
  }

  public void assertErrorAlert(HtmlPage keyManagementPage, String... expectedMessage)
  {
    assertAlert(keyManagementPage, expectedMessage, "alertERROR");
  }


}

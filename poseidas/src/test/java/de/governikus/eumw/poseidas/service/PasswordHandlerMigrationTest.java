package de.governikus.eumw.poseidas.service;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.IOException;

import org.apache.commons.io.FileUtils;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.test.context.ActiveProfiles;

import de.governikus.eumw.poseidas.config.OverviewController;


@ActiveProfiles("test") // Use application-test.properties
@SpringBootTest
class PasswordHandlerMigrationTest
{

  public static final String PASSWORD_PROPERTIES = "password.properties";

  @Autowired
  PasswordHandler passwordHandler;

  @MockBean
  private OverviewController overviewController;

  @TempDir
  static File tempDir;

  @BeforeAll
  static void setup() throws IOException
  {
    System.setProperty("spring.config.additional-location", tempDir.getAbsolutePath() + "/");
    FileUtils.copyFile(new File("./src/test/resources/application-test.properties"),
                       new File(System.getProperty("spring.config.additional-location")
                                + "/application-test.properties"));
  }

  @AfterEach
  void cleanPasswordProperties()
  {
    new File(tempDir, PASSWORD_PROPERTIES).delete();
  }

  @AfterAll
  static void cleanUp()
  {
    System.clearProperty("spring.config.additional-location");
  }

  @Test
  void migratePassword()
  {
    assertTrue(passwordHandler.isApplicationPropertiesPasswordSet());
    // Check that no password.properties exists yet
    assertFalse(new File(tempDir.getAbsolutePath(), PASSWORD_PROPERTIES).exists());
    // isPasswordSet also migrates the password
    assertTrue(passwordHandler.isPasswordSet());
    // Check that password.properties and password exists
    assertTrue(new File(tempDir.getAbsolutePath(), PASSWORD_PROPERTIES).exists());
    assertTrue(BCrypt.checkpw(PasswordHandlerTest.PASSWORD, passwordHandler.getHashedPassword()));
  }

  @Test
  void passwordIsAlreadySet() throws IOException
  {
    // A password is set in application.properties
    assertTrue(passwordHandler.isApplicationPropertiesPasswordSet());
    // Check that no password is set yet in password.properties
    assertFalse(new File(tempDir.getAbsolutePath(), PASSWORD_PROPERTIES).exists());
    // Set a password before trying to migrate
    String newPassword = "NichtWurst";
    passwordHandler.updatePassword(newPassword, false);
    assertTrue(new File(tempDir.getAbsolutePath(), PASSWORD_PROPERTIES).exists());
    // isPasswordSet migrates the password from application.properties if it is not already set
    assertTrue(passwordHandler.isPasswordSet());
    // Try to authenticate with password from application.properties
    assertFalse(BCrypt.checkpw(PasswordHandlerTest.PASSWORD, passwordHandler.getHashedPassword()));
    // Try with new password set before migration
    assertTrue(BCrypt.checkpw(newPassword, passwordHandler.getHashedPassword()));
  }

  @Test
  void userIsSet()
  {
    // In this application-test.properties a user is set
    assertTrue(passwordHandler.isApplicationPropertiesUserSet());
  }
}

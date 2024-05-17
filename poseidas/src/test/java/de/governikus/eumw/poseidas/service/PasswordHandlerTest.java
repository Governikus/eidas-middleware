package de.governikus.eumw.poseidas.service;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.IOException;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.crypto.bcrypt.BCrypt;

import de.governikus.eumw.poseidas.config.IndexController;


@SpringBootTest
class PasswordHandlerTest
{

  public static final String PASSWORD = "wurst";

  @MockBean
  private IndexController overviewController;

  @Autowired
  PasswordHandler passwordHandler;

  @TempDir
  File tempDir;

  @BeforeEach
  void setup()
  {
    System.setProperty("spring.config.additional-location", tempDir.getAbsolutePath() + "/");
  }

  @AfterAll
  static void cleanUp()
  {
    System.clearProperty("spring.config.additional-location");
  }

  @Test
  void passwordNotSet()
  {
    PasswordHandler passwordHandler = new PasswordHandler();
    assertFalse(passwordHandler.isPasswordSet());
  }

  @Test
  void updatePassword() throws IOException
  {
    PasswordHandler passwordHandler = new PasswordHandler();
    passwordHandler.updatePassword(PASSWORD, false);
    assertTrue(passwordHandler.isPasswordSet());
    assertTrue(BCrypt.checkpw(PASSWORD, passwordHandler.getHashedPassword()));
  }

  @Test
  void passwordMigrationWithDefaultPassword()
  {
    // This test uses @Autowired instance of PasswordHandler because it fetches the hashed password set in
    // application.properties. This should be: $2a$10$lRmdsCOtjoBLb8bKDrviueoW1aUkIcUmnImu4xZlOzvfc5k9WcKAi
    assertTrue(passwordHandler.isApplicationPropertiesPasswordSet());
    // This method also tries to migrate the password, which is the forbidden default password
    assertFalse(passwordHandler.isPasswordSet());
  }

  @Test
  void userIsNotSet()
  {
    // In this application.properties no user is set
    assertFalse(passwordHandler.isApplicationPropertiesUserSet());
  }
}

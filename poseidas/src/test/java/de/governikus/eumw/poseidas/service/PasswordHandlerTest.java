package de.governikus.eumw.poseidas.service;

import java.io.File;
import java.io.IOException;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import de.governikus.eumw.poseidas.config.IndexController;


@SpringBootTest
class PasswordHandlerTest
{

  public static final String PASSWORD = "wurst";

  @MockitoBean
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
  void testUpdatePassword() throws IOException
  {
    PasswordHandler pwHandler = new PasswordHandler();
    Assertions.assertFalse(pwHandler.isPasswordSet());
    pwHandler.updatePassword(PASSWORD, false);
    Assertions.assertTrue(pwHandler.isPasswordSet());
    Assertions.assertTrue(BCrypt.checkpw(PASSWORD, pwHandler.getHashedPassword()));
  }

  @Test
  void testThrows()
  {
    Assertions.assertThrows(IOException.class, () -> passwordHandler.updatePassword(PASSWORD, false));
  }

  @Test
  void testVerifyOldPassword() throws IOException
  {
    PasswordHandler pwName = new PasswordHandler();
    pwName.updatePassword(PASSWORD, false);
    Assertions.assertTrue(pwName.verifyOldPassword(PASSWORD));
    Assertions.assertFalse(pwName.verifyOldPassword("123"));
    Assertions.assertFalse(pwName.verifyOldPassword(null));
  }

  @Test
  void testPasswortMigration()
  {
    // This test uses @Autowired instance of PasswordHandler because it fetches the hashed password set in
    // application.properties. This should be: $2a$10$lRmdsCOtjoBLb8bKDrviueoW1aUkIcUmnImu4xZlOzvfc5k9WcKAi
    Assertions.assertTrue(passwordHandler.isApplicationPropertiesPasswordSet());
    // This method also tries to migrate the password, which is the forbidden default password
    Assertions.assertFalse(passwordHandler.isPasswordSet());
  }

  @Test
  void testUserIsNotSet()
  {
    // In this application.properties no user is set
    Assertions.assertFalse(passwordHandler.isApplicationPropertiesUserSet());
  }
}

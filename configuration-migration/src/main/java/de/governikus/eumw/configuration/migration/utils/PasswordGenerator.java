package de.governikus.eumw.configuration.migration.utils;

import java.security.SecureRandom;
import java.util.Random;

import org.apache.commons.lang3.RandomStringUtils;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;


/**
 * a utility class for generating passwords or similar
 *
 * @author Pascal Knüppel
 * @since 12.05.2021
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class PasswordGenerator
{

  private static final Random RANDOM = new SecureRandom();

  /**
   * generates a random password
   */
  public static char[] generateRandomPassword()
  {
    int randomStrLength = RANDOM.nextInt(10) + 25;
    char[] possibleCharacters = ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789`!@#$%*()"
                                 + "-_=+[{]}\\|;:,./?").toCharArray();
    return RandomStringUtils.random(randomStrLength,
                                    0,
                                    possibleCharacters.length - 1,
                                    false,
                                    false,
                                    possibleCharacters,
                                    new SecureRandom())
                            .toCharArray();
  }
}

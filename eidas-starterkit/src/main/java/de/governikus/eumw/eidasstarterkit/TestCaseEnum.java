package de.governikus.eumw.eidasstarterkit;

import de.governikus.eumw.eidascommon.ErrorCode;


/**
 * An enum for the different test cases.
 */
public enum TestCaseEnum
{

  CANCELLATION_BY_USER("CANCELLATIONBYUSER", ErrorCode.CANCELLATION_BY_USER),

  WRONG_PIN("WRONGPIN", ErrorCode.AUTHORIZATION_FAILED),

  WRONG_SIGNATURE("WRONGSIGNATURE", ErrorCode.EID_ERROR),

  CARD_EXPIRED("CARDEXPIRED", ErrorCode.EID_ERROR),

  UNKNOWN("UNKNOWN", ErrorCode.INTERNAL_ERROR);

  private final String testCase;

  private final ErrorCode errorCode;

  private TestCaseEnum(String testCase, ErrorCode errorCode)
  {
    this.testCase = testCase;
    this.errorCode = errorCode;
  }

  /**
   * Get the test case.
   *
   * @return name of the test case enum.
   */
  public String getTestCase()
  {
    return testCase;
  }

  /**
   * Get the error code of the test case enum.
   *
   * @return error code of the test case enum.
   */
  public ErrorCode getErrorCode()
  {
    return errorCode;
  }

  /**
   * Parsed a {@link String} to get a {@link TestCaseEnum}.
   *
   * @param testCase the test case to parse.
   * @return TestCaseEnum when present, otherwise null.
   */
  public static TestCaseEnum parse(String testCase)
  {
    for ( TestCaseEnum testCaseEnum : TestCaseEnum.values() )
    {
      if (testCaseEnum.getTestCase().equalsIgnoreCase(testCase))
      {
        return testCaseEnum;
      }
    }
    return null;
  }
}

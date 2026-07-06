package de.governikus.eumw.eidasstarterkit.additional.attributes;

import org.junit.jupiter.api.Assertions;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;


class NationalityTypeImplTest
{

  private NationalityTypeImpl createInstance()
  {
    return new NationalityTypeImpl("urn:test", "Nationality", "eidas");
  }

  @Test
  void testToStringValueReturnsConfiguredValue()
  {
    NationalityTypeImpl nationality = createInstance();

    nationality.setValue("DE");

    Assertions.assertEquals("DE", nationality.toStringValue());
  }

  @Test
  void testParseStringValueAcceptsValidNationality()
  {
    NationalityTypeImpl nationality = createInstance();

    nationality.parseStringValue("DE");

    Assertions.assertEquals("DE", nationality.getValue());
  }

  @ParameterizedTest
  @NullSource
  @ValueSource(strings = {"de", "D", "DEU", "1D", "D1", "##"})
  void testParseStringValueIgnoresInvalidValues(String value)
  {
    NationalityTypeImpl nationality = createInstance();

    nationality.parseStringValue(value);

    Assertions.assertNull(nationality.getValue());
  }

  @Test
  void testParseStringValueDoesNotOverwriteExistingValueWithInvalidInput()
  {
    NationalityTypeImpl nationality = createInstance();

    nationality.setValue("DE");

    nationality.parseStringValue("de");

    Assertions.assertEquals("DE", nationality.getValue());
  }
}

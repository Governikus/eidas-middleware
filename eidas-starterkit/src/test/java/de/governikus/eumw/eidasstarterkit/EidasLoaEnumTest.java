package de.governikus.eumw.eidasstarterkit;

import java.util.stream.Stream;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.api.Test;

import se.swedenconnect.opensaml.eidas.common.EidasConstants;


class EidasLoaEnumTest
{

  @ParameterizedTest
  @MethodSource("parseValues")
  void testParseValues(String uri, EidasLoaEnum expected)
  {
    Assertions.assertEquals(expected, EidasLoaEnum.parse(uri));
  }

  static Stream<Arguments> parseValues()
  {
    return Stream.of(Arguments.of(EidasConstants.EIDAS_LOA_LOW_NON_NOTIFIED, EidasLoaEnum.LOA_LOW_NON_NOTIFIED),
                     Arguments.of(EidasConstants.EIDAS_LOA_LOW_NON_NOTIFIED2, EidasLoaEnum.LOA_LOW_NON_NOTIFIED),
                     Arguments.of(EidasConstants.EIDAS_LOA_LOW, EidasLoaEnum.LOA_LOW),
                     Arguments.of(EidasConstants.EIDAS_LOA_SUBSTANTIAL_NON_NOTIFIED,
                                  EidasLoaEnum.LOA_SUBSTANTIAL_NON_NOTIFIED),
                     Arguments.of(EidasConstants.EIDAS_LOA_SUBSTANTIAL_NON_NOTIFIED2,
                                  EidasLoaEnum.LOA_SUBSTANTIAL_NON_NOTIFIED),
                     Arguments.of(EidasConstants.EIDAS_LOA_SUBSTANTIAL, EidasLoaEnum.LOA_SUBSTANTIAL),
                     Arguments.of(EidasConstants.EIDAS_LOA_HIGH_NON_NOTIFIED, EidasLoaEnum.LOA_HIGH_NON_NOTIFIED),
                     Arguments.of(EidasConstants.EIDAS_LOA_HIGH_NON_NOTIFIED2, EidasLoaEnum.LOA_HIGH_NON_NOTIFIED),
                     Arguments.of(EidasConstants.EIDAS_LOA_HIGH, EidasLoaEnum.LOA_HIGH),
                     Arguments.of("test", EidasLoaEnum.LOA_TEST));
  }

  @Test
  void testParseValuesFails()
  {
    Assertions.assertNull(EidasLoaEnum.parse("unknown"));
    Assertions.assertNull(EidasLoaEnum.parse(null));
  }

  @Test
  void testGetUri()
  {
    Assertions.assertEquals(EidasConstants.EIDAS_LOA_LOW_NON_NOTIFIED, EidasLoaEnum.LOA_LOW_NON_NOTIFIED.getUri());
    Assertions.assertEquals(EidasConstants.EIDAS_LOA_LOW, EidasLoaEnum.LOA_LOW.getUri());
    Assertions.assertEquals(EidasConstants.EIDAS_LOA_SUBSTANTIAL_NON_NOTIFIED,
                            EidasLoaEnum.LOA_SUBSTANTIAL_NON_NOTIFIED.getUri());
    Assertions.assertEquals(EidasConstants.EIDAS_LOA_SUBSTANTIAL, EidasLoaEnum.LOA_SUBSTANTIAL.getUri());
    Assertions.assertEquals(EidasConstants.EIDAS_LOA_HIGH_NON_NOTIFIED, EidasLoaEnum.LOA_HIGH_NON_NOTIFIED.getUri());
    Assertions.assertEquals(EidasConstants.EIDAS_LOA_HIGH, EidasLoaEnum.LOA_HIGH.getUri());
    Assertions.assertEquals("test", EidasLoaEnum.LOA_TEST.getUri());
  }

  @Test
  void testGetOrder()
  {
    Assertions.assertEquals(0, EidasLoaEnum.LOA_TEST.getOrder());
    Assertions.assertEquals(1, EidasLoaEnum.LOA_LOW_NON_NOTIFIED.getOrder());
    Assertions.assertEquals(2, EidasLoaEnum.LOA_LOW.getOrder());
    Assertions.assertEquals(3, EidasLoaEnum.LOA_SUBSTANTIAL_NON_NOTIFIED.getOrder());
    Assertions.assertEquals(4, EidasLoaEnum.LOA_SUBSTANTIAL.getOrder());
    Assertions.assertEquals(5, EidasLoaEnum.LOA_HIGH_NON_NOTIFIED.getOrder());
    Assertions.assertEquals(6, EidasLoaEnum.LOA_HIGH.getOrder());
  }
}

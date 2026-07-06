package de.governikus.eumw.poseidas.eidserver.convenience;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.stream.Stream;
import java.util.zip.Deflater;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import de.governikus.eumw.poseidas.cardserver.eac.functions.read.ReadResult;
import de.governikus.panstar.sdk.utils.constant.EIDAttributeName;


class ASN1ParserTest
{

  private EIDSequence parent;

  private ReadResult readResult;

  @BeforeEach
  void setup()
  {
    parent = mock(EIDSequence.class);
    readResult = mock(ReadResult.class);
  }

  @Nested
  @TestInstance(TestInstance.Lifecycle.PER_CLASS)
  class AddressParsingTests
  {

    Stream<EIDAttributeName> addressAttributes()
    {
      return Stream.of(EIDAttributeName.PlaceOfBirth, EIDAttributeName.PlaceOfResidence);
    }

    @ParameterizedTest
    @MethodSource("addressAttributes")
    void freeText_is_parsed(EIDAttributeName attribute) throws IOException
    {
      String freeText = "Free Text Address";
      ASN1TaggedObject inner = new DERTaggedObject(1, new DERUTF8String(freeText));
      ASN1TaggedObject taggedObject = new DERTaggedObject(attribute.getSfi(), inner);

      when(readResult.getData()).thenReturn(taggedObject.getEncoded());

      EIDInfoResult result = ASN1Parser.getASN1Value(readResult, attribute, parent);

      assertInstanceOf(EIDInfoResultPlaceFreeText.class, result);
      assertEquals(freeText, ((EIDInfoResultPlaceFreeText)result).getFreeTextPlace());
    }

    @ParameterizedTest
    @MethodSource("addressAttributes")
    void placeNo_is_parsed(EIDAttributeName attribute) throws IOException
    {
      String value = "No registered place";
      ASN1TaggedObject inner = new DERTaggedObject(2, new DERUTF8String(value));
      ASN1TaggedObject taggedObject = new DERTaggedObject(attribute.getSfi(), inner);

      when(readResult.getData()).thenReturn(taggedObject.getEncoded());

      EIDInfoResult result = ASN1Parser.getASN1Value(readResult, attribute, parent);

      assertInstanceOf(EIDInfoResultPlaceNo.class, result);
      assertEquals(value, ((EIDInfoResultPlaceNo)result).getNoPlaceInfo());
    }

    @ParameterizedTest
    @MethodSource("addressAttributes")
    void structured_place_is_parsed(EIDAttributeName attribute) throws IOException
    {
      byte[] asnBytes = loadAsn1StructuredPlaceBytes(attribute);

      when(readResult.getData()).thenReturn(asnBytes);

      EIDInfoResult result = ASN1Parser.getASN1Value(readResult, attribute, parent);

      assertInstanceOf(EIDInfoResultPlaceStructured.class, result);

      EIDInfoResultPlaceStructured addr = (EIDInfoResultPlaceStructured)result;
      assertEquals("Musterstrasse 1", addr.getStreet());
      assertEquals("Musterstadt", addr.getCity());
      assertEquals("Musterland", addr.getState());
      assertEquals("Deutschland", addr.getCountry());
      assertEquals("12345", addr.getZipCode());
    }

  }

  @Nested
  class ResidencePermitParsingTests
  {

    @Test
    void uncompressed_text_is_parsed() throws IOException
    {
      String permit = "Permit123";
      ASN1TaggedObject inner = new DERTaggedObject(true, 1, new DERUTF8String(permit));
      ASN1TaggedObject taggedObject = new DERTaggedObject(EIDAttributeName.ResidencePermitI.getSfi(), inner);

      when(readResult.getData()).thenReturn(taggedObject.getEncoded());

      EIDInfoResult result = ASN1Parser.getASN1Value(readResult, EIDAttributeName.ResidencePermitI, parent);

      assertInstanceOf(EIDInfoResultString.class, result);
      assertEquals(permit, ((EIDInfoResultString)result).getResult());
    }

    @Test
    void compressed_text_is_parsed() throws IOException
    {
      String permit = "Permit123";
      ASN1TaggedObject inner = new DERTaggedObject(1, new DERUTF8String(permit));
      byte[] compressed = compress(inner.getEncoded());

      ASN1TaggedObject taggedObject = new DERTaggedObject(EIDAttributeName.ResidencePermitI.getSfi(),
                                                          new DERTaggedObject(2, new DEROctetString(compressed)));

      when(readResult.getData()).thenReturn(taggedObject.getEncoded());

      EIDInfoResult result = ASN1Parser.getASN1Value(readResult, EIDAttributeName.ResidencePermitI, parent);

      assertInstanceOf(EIDInfoResultPlaceNo.class, result);
      assertEquals(permit, ((EIDInfoResultPlaceNo)result).getNoPlaceInfo());
    }

    @Test
    void unknown_residence_permit_choice_returns_null() throws IOException
    {
      ASN1TaggedObject inner = new DERTaggedObject(99, new DERUTF8String("XXX"));
      ASN1TaggedObject taggedObject = new DERTaggedObject(EIDAttributeName.ResidencePermitI.getSfi(), inner);

      when(readResult.getData()).thenReturn(taggedObject.getEncoded());

      EIDInfoResult result = ASN1Parser.getASN1Value(readResult, EIDAttributeName.ResidencePermitI, parent);

      assertNull(result);
    }

    @Test
    void non_tagged_asn1_returns_null() throws IOException
    {
      ASN1Primitive primitive = new DERUTF8String("not tagged ASN.1");
      ASN1TaggedObject top = new DERTaggedObject(EIDAttributeName.ResidencePermitI.getSfi(), primitive);

      when(readResult.getData()).thenReturn(top.getEncoded());

      EIDInfoResult result = ASN1Parser.getASN1Value(readResult, EIDAttributeName.ResidencePermitI, parent);

      assertNull(result);
    }
  }

  @Nested
  class CommunityIdParsingTests
  {

    @Test
    void valid_octet_string_is_parsed() throws IOException
    {
      byte[] octets = new byte[]{0x01, 0x02, 0x03, 0x04};
      ASN1OctetString octetString = new DEROctetString(octets);
      ASN1TaggedObject taggedObject = new DERTaggedObject(EIDAttributeName.CommunityID.getSfi(), octetString);

      when(readResult.getData()).thenReturn(taggedObject.getEncoded());

      EIDInfoResult result = ASN1Parser.getASN1Value(readResult, EIDAttributeName.CommunityID, parent);

      assertInstanceOf(EIDInfoResultByteArray.class, result);
      assertArrayEquals(octets, ((EIDInfoResultByteArray)result).getResult());
    }

    @Test
    void invalid_type_returns_null() throws IOException
    {
      ASN1TaggedObject taggedObject = new DERTaggedObject(EIDAttributeName.CommunityID.getSfi(),
                                                          new DERUTF8String("not octets"));

      when(readResult.getData()).thenReturn(taggedObject.getEncoded());

      EIDInfoResult result = ASN1Parser.getASN1Value(readResult, EIDAttributeName.CommunityID, parent);
      assertNull(result);
    }
  }

  @Nested
  class SimpleAsn1FieldTests
  {

    @Test
    void asn1StringParsing_returnsValue() throws IOException
    {
      String value = "Mustermann";
      ASN1TaggedObject taggedObject = new DERTaggedObject(EIDAttributeName.FamilyNames.getSfi(),
                                                          new DERUTF8String(value));

      when(readResult.getData()).thenReturn(taggedObject.getEncoded());

      EIDInfoResult result = ASN1Parser.getASN1Value(readResult, EIDAttributeName.FamilyNames, parent);

      assertInstanceOf(EIDInfoResultString.class, result);
      assertEquals(value, ((EIDInfoResultString)result).getResult());
    }

    @Test
    void asn1OctetStringParsing_returnsValue() throws IOException
    {
      String value = "Mustermann";
      DEROctetString octetString = new DEROctetString(value.getBytes(StandardCharsets.UTF_8));
      ASN1TaggedObject taggedObject = new DERTaggedObject(EIDAttributeName.FamilyNames.getSfi(), octetString);

      when(readResult.getData()).thenReturn(taggedObject.getEncoded());

      EIDInfoResult result = ASN1Parser.getASN1Value(readResult, EIDAttributeName.FamilyNames, parent);

      assertInstanceOf(EIDInfoResultString.class, result);
      assertEquals(value, ((EIDInfoResultString)result).getResult());
    }

    @Test
    void unsupportedAsn1Type_returnsNull() throws IOException
    {
      ASN1TaggedObject taggedObject = new DERTaggedObject(EIDAttributeName.FamilyNames.getSfi(), new ASN1Integer(42));

      when(readResult.getData()).thenReturn(taggedObject.getEncoded());

      EIDInfoResult result = ASN1Parser.getASN1Value(readResult, EIDAttributeName.FamilyNames, parent);
      assertNull(result);
    }
  }

  // OTHER RETURN NULL CASES

  @Test
  void testGetASN1ValueWithUnexpectedTagReturnsNull() throws IOException
  {
    ASN1TaggedObject taggedObject = new DERTaggedObject(EIDAttributeName.PlaceOfBirth.getSfi() + 1,
                                                        new DERUTF8String("X"));

    when(readResult.getData()).thenReturn(taggedObject.getEncoded());

    EIDInfoResult result = ASN1Parser.getASN1Value(readResult, EIDAttributeName.PlaceOfBirth, parent);
    assertNull(result);
  }

  @Test
  void testGetASN1ValueForInvalidAsn1ReturnsNull()
  {
    when(readResult.getData()).thenReturn(new byte[]{0x01, 0x02}); // invalid ASN.1

    EIDInfoResult result = ASN1Parser.getASN1Value(readResult, EIDAttributeName.PlaceOfBirth, parent);
    Assertions.assertNull(result);
  }

  @Test
  void structured_address_missing_mandatory_field_returns_null() throws IOException
  {
    // only city is given
    ASN1Sequence asn1Sequence = new DERSequence(new ASN1Encodable[]{new DERTaggedObject(11,
                                                                                        new DERUTF8String("Musterstadt"))});

    ASN1TaggedObject taggedObject = new DERTaggedObject(EIDAttributeName.PlaceOfBirth.getSfi(), asn1Sequence);

    when(readResult.getData()).thenReturn(taggedObject.getEncoded());

    EIDInfoResult result = ASN1Parser.getASN1Value(readResult, EIDAttributeName.PlaceOfBirth, parent);

    assertNull(result);
  }

  // HELPER METHODS

  private static byte[] loadAsn1StructuredPlaceBytes(EIDAttributeName attribute) throws IOException
  {
    ASN1Encodable street = new DERTaggedObject(10, new DERUTF8String("Musterstrasse 1"));
    ASN1Encodable city = new DERTaggedObject(11, new DERUTF8String("Musterstadt"));
    ASN1Encodable state = new DERTaggedObject(12, new DERUTF8String("Musterland"));
    ASN1Encodable country = new DERTaggedObject(13, new DERPrintableString("Deutschland"));
    ASN1Encodable zip = new DERTaggedObject(14, new DERPrintableString("12345"));

    ASN1Sequence structuredPlaceSequence = new DERSequence(new ASN1Encodable[]{street, city, state, country, zip});
    ASN1TaggedObject taggedObject = new DERTaggedObject(attribute.getSfi(), structuredPlaceSequence);

    return taggedObject.getEncoded();
  }

  private static byte[] compress(byte[] data) throws IOException
  {
    Deflater deflater = new Deflater(Deflater.DEFAULT_COMPRESSION, true);
    deflater.setInput(data);
    deflater.finish();
    try (ByteArrayOutputStream baos = new ByteArrayOutputStream())
    {
      byte[] buffer = new byte[1024];
      while (!deflater.finished())
      {
        int count = deflater.deflate(buffer);
        baos.write(buffer, 0, count);
      }
      return baos.toByteArray();
    }
    finally
    {
      deflater.end();
    }
  }
}

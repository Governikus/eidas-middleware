package de.governikus.eumw.poseidas.eidserver.convenience;


import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1PrintableString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.ASN1UTF8String;

import de.governikus.eumw.poseidas.cardserver.eac.functions.read.ReadResult;
import de.governikus.panstar.sdk.utils.constant.EIDAttributeName;
import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;


@Slf4j
@UtilityClass
class ASN1Parser
{

  static final String LOG_DATA = "[Transmit data]";

  /**
   * Parses the ASN.1 value for the given EID attribute from the provided read result.
   *
   * @param readResult the source ASN.1-encoded data
   * @param dataFieldName the EID attribute to extract
   * @param parent the parent sequence, used for logging
   * @return the parsed {@link EIDInfoResult}, or {@code null} if parsing fails
   * @throws IllegalArgumentException if the ASN.1 tag does not match the expected EID attribute
   */
  static EIDInfoResult getASN1Value(ReadResult readResult, EIDAttributeName dataFieldName, EIDSequence parent)
  {
    try (ASN1InputStream asn1InputStream = new ASN1InputStream(readResult.getData()))
    {
      ASN1TaggedObject taggedObject = ASN1TaggedObject.getInstance(asn1InputStream.readObject());

      // check that the object matches the attribute
      if (taggedObject.getTagNo() != dataFieldName.getSfi())
      {
        throw new IllegalArgumentException("The field " + dataFieldName.name() + " does not have the expected tag.");
      }

      ASN1Primitive asn1Primitive = taggedObject.getBaseObject().toASN1Primitive();

      switch (dataFieldName)
      {
        case PlaceOfBirth, PlaceOfResidence:
          return parseAddress(asn1Primitive);

        case ResidencePermitI:
          return parseResidencePermit(asn1Primitive);

        case CommunityID:
          return parseCommunityId(asn1Primitive);

        default:
          String fieldValue = extractUtf8String(asn1Primitive);
          log.debug("{}{}[ASN1 Simple] : {}", parent.getLogPrefix(), LOG_DATA, fieldValue);
          return new EIDInfoResultString(fieldValue);
      }
    }
    catch (IOException e)
    {
      log.error("{}{}Can't get FileContent for field: {}", parent.getLogPrefix(), LOG_DATA, dataFieldName, e);
      return null;
    }
    catch (IllegalArgumentException e)
    {
      log.error("The field {} cannot be parsed: ", dataFieldName, e);
      return null;
    }
  }

  /**
   * Parses a GeneralPlace ASN.1 structure into an {@link EIDInfoResult}.
   *
   * @param asn1Primitive the ASN.1 primitive representing the place
   * @return an {@link EIDInfoResult} representing the parsed place
   * @throws IOException if the ASN.1 structure or tag is unexpected
   */
  private static EIDInfoResult parseAddress(ASN1Primitive asn1Primitive) throws IOException
  {
    if (asn1Primitive instanceof ASN1TaggedObject tagged)
    {
      ASN1Primitive baseObject = (ASN1Primitive)tagged.getBaseObject();

      return switch (tagged.getTagNo())
      {
        case 1 -> new EIDInfoResultPlaceFreeText(extractUtf8String(baseObject));
        case 2 -> new EIDInfoResultPlaceNo(extractUtf8String(baseObject));
        default -> throw new IOException("Unexpected address tag: " + tagged.getTagNo());
      };
    }

    if (asn1Primitive instanceof ASN1Sequence seq) // structuredPlace
    {
      String street = getASNAddress(seq, (byte)0xaa);
      String city = getASNAddress(seq, (byte)0xab);
      String state = getASNAddress(seq, (byte)0xac);
      String country = getASNAddress(seq, (byte)0xad);
      String zip = getASNAddress(seq, (byte)0xae);

      return new EIDInfoResultPlaceStructured(street, city, state, country, zip);
    }

    throw new IOException("Unexpected address format");
  }


  private static String getASNAddress(ASN1Sequence place, byte tag) throws IOException
  {
    int tagNo = tag & 0x1F; // extract ASN.1 tag number (e.g. tag = 0xAA -> tagNo = 10)

    String match = null; // store the matching value

    for ( ASN1Encodable asn1Encodable : place.toArray() )
    {
      if (asn1Encodable instanceof ASN1TaggedObject tagged && tagged.getTagNo() == tagNo)
      {
        byte[] encoded = tagged.getBaseObject().getEncoded();
        match = switch (tagNo)
        {
          case 10, 11, 12 -> readUTF8String(encoded); // street, city, state
          case 13 -> readICAOCountry(encoded); // country
          case 14 -> readPrintableString(encoded); // zip
          default -> throw new IOException("Unexpected address tag: " + tagNo);
        };

        break; // match found
      }
    }

    if (match != null)
    {
      return match;
    }

    // === no match found ===
    if (tagNo == 10 || tagNo == 12 || tagNo == 14)
    {
      return null;
    }
    throw new IOException(tag + " tag for address is no optional field and must be filled");
  }

  /**
   * Parses an ASN.1-encoded residence permit value and returns it as an {@link EIDInfoResult}.
   *
   * @param value the ASN.1 primitive representing the residence permit
   * @return the parsed {@link EIDInfoResult}, or {@code null} if the value is not a tagged object
   * @throws IOException if parsing or decompression fails
   * @throws IllegalArgumentException if the tag number is unknown
   */
  private static EIDInfoResult parseResidencePermit(ASN1Primitive value) throws IOException
  {
    if (!(value instanceof ASN1TaggedObject tagged))
    {
      return null;
    }

    return switch (tagged.getTagNo())
    {
      // [1] extract from a UTF-8 string
      case 1 -> parseUncompressedText(tagged);
      // [2] the residence Permit is contained in compressed text -> decompress first and then extract
      // the UTF-8 String
      case 2 -> parseCompressedText(tagged);
      default -> throw new IllegalArgumentException("Received unknown residence permit choice tag");
    };
  }

  private static EIDInfoResultString parseUncompressedText(ASN1TaggedObject tagged)
  {
    ASN1UTF8String asn1UTF8String = ASN1UTF8String.getInstance(tagged.getBaseObject().toASN1Primitive());
    return new EIDInfoResultString(asn1UTF8String.getString());
  }

  private static EIDInfoResult parseCompressedText(ASN1TaggedObject tagged) throws IOException
  {
    byte[] octets = ASN1OctetString.getInstance(tagged.getBaseObject()).getOctets(); // contains compressed bytes
    byte[] inflated = decompress(octets);
    ASN1Primitive asn1 = ASN1Primitive.fromByteArray(inflated); // decode bytes as asn1
    // the decompressed object should now be a UTF8-String
    ASN1TaggedObject innerTagged = ASN1TaggedObject.getInstance(asn1);
    ASN1UTF8String asn1UTF8String = ASN1UTF8String.getInstance(innerTagged.getBaseObject());
    return new EIDInfoResultPlaceNo(asn1UTF8String.getString());
  }

  /**
   * Parses an ASN.1-encoded Community ID as an OCTET STRING and returns it as an {@link EIDInfoResultByteArray}.
   *
   * @param value the ASN.1 primitive representing the Community ID
   * @return the parsed {@link EIDInfoResultByteArray} containing the octets
   * @throws IOException if the value is not a valid OCTET STRING
   */
  private static EIDInfoResult parseCommunityId(ASN1Primitive value) throws IOException
  {
    try
    {
      ASN1OctetString oct = ASN1OctetString.getInstance(value);
      return new EIDInfoResultByteArray(oct.getOctets());
    }
    catch (IllegalArgumentException e)
    {
      throw new IOException("CommunityID cannot be interpreted as an OCTET STRING", e);
    }
  }

  private static String extractUtf8String(ASN1Primitive p) throws IOException
  {
    if (p instanceof ASN1String s)
    {
      return s.getString();
    }
    if (p instanceof ASN1OctetString octets)
    {
      return new String(octets.getOctets(), StandardCharsets.UTF_8);
    }
    throw new IOException("Cannot extract string from ASN.1 type: " + p.getClass());
  }

  private static String readPrintableString(byte[] data)
  {
    return ASN1PrintableString.getInstance(data).getString();
  }

  private static String readICAOCountry(byte[] data)
  {
    return readICAOString(data);
  }

  private static String readICAOString(byte[] data)
  {
    return readPrintableString(data);
  }

  private static String readUTF8String(byte[] data)
  {
    return ASN1UTF8String.getInstance(data).getString();
  }

  private static byte[] decompress(byte[] compressed) throws IOException
  {
    try (Inflater inflater = new Inflater(true))
    {
      inflater.setInput(compressed);

      try (ByteArrayOutputStream baos = new ByteArrayOutputStream())
      {
        byte[] buffer = new byte[1024];
        while (!inflater.finished())
        {
          int count;
          try
          {
            count = inflater.inflate(buffer);
          }
          catch (DataFormatException e)
          {
            throw new IOException("Failed to inflate the data", e);
          }

          if (count == 0 && inflater.needsInput())
          {
            break;
          }
          baos.write(buffer, 0, count);
        }
        return baos.toByteArray();
      }
      finally
      {
        inflater.end();
      }
    }
  }
}

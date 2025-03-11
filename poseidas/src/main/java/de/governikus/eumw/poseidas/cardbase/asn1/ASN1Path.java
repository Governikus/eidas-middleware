/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardbase.asn1;

import java.math.BigInteger;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import de.governikus.eumw.poseidas.cardbase.AssertUtil;
import de.governikus.eumw.poseidas.cardbase.Filter;
import de.governikus.eumw.poseidas.cardbase.Hex;


/**
 * ASN.1-Path for description of a child element of an {@link ASN1}.
 *
 * @author Arne Stahlbock, ast@bos-bremen.de
 * @author Jens Wothe, jw@bos-bremen.de
 */
public class ASN1Path
{

  /**
   * Constant argument name: <tt>filter</tt>.
   */
  private static final String STRING_FILTER = "filter";

  /**
   * Constant argument name: <tt>tag hex string</tt>.
   */
  private static final String STRING_TAG_HEX_STRING = "tag hex string";

  /**
   * Constant argument name: <tt>type</tt>.
   */
  private static final String STRING_TYPE = "type";

  /**
   * Constant argument name: <tt>tag</tt>.
   */
  private static final String STRING_TAG = "tag";

  /**
   * {@link Logger} instance.
   */
  private static final Log LOG = LogFactory.getLog(ASN1Path.class.getName());

  /**
   * Constant of index indicating index not used to specify child, filter is used instead: <code>-1</code>.
   */
  private static final int NO_INDEX = -1;

  // filter
  private Filter<ASN1> filter = null;

  /**
   * Gets ASN1 filter.
   *
   * @return the ASN1 filter
   */
  public final Filter<ASN1> getFilter()
  {
    return this.filter;
  }

  // name
  private String name = "";

  // parent path element
  private ASN1Path parent = null;

  // tag of child element
  private BigInteger tag = null;

  // index of child element
  private int index = 0;

  private ASN1PathType type = null;

  // class for encoding information as ASN.1
  private Class<? extends ASN1Encoder> encoderClass = null;

  /**
   * Constructor.
   *
   * @param name name, <code>null</code> or empty String permitted
   * @param tag tag of child element, <code>null</code> not permitted, must specify a valid tag
   * @param index index of child element, only zero or positive value permitted
   * @param parent optional parent path element
   * @see ASN1Path#ASN1Path(String, BigInteger, int, ASN1Path, Class, ASN1PathType)
   * @see ASN1PathType#NO_INFORMATION
   */
  protected ASN1Path(String name, BigInteger tag, int index, ASN1Path parent)
  {
    this(name, AssertUtil.notNullReturn(tag, STRING_TAG), index, parent, null, ASN1PathType.NO_INFORMATION);
  }

  /**
   * Constructor.
   *
   * @param name name, <code>null</code> or empty String permitted
   * @param tagBytes tag bytes of child element, <code>null</code> or empty array not permitted, must specify
   *          a valid tag
   * @param index index of child element, only zero or positive value permitted
   * @param parent optional parent path element
   * @throws IllegalArgumentException if arguments not valid
   * @see ASN1Path#ASN1Path(String, BigInteger, int, ASN1Path, Class, ASN1PathType)
   * @see ASN1PathType#NO_INFORMATION
   */
  protected ASN1Path(String name, byte[] tagBytes, int index, ASN1Path parent)
  {
    this(name, new BigInteger(ASN1Util.checkTagBytes(tagBytes)), index, parent, null,
         ASN1PathType.NO_INFORMATION);
  }

  /**
   * Constructor.
   *
   * @param name name, <code>null</code> or empty String permitted
   * @param tagHexString tag of child element as Hex-String, <code>null</code> or empty String not permitted,
   *          must specify a valid tag
   * @param index index of child element, only zero or positive value permitted
   * @param parent optional parent path element
   * @throws IllegalArgumentException if arguments not valid
   * @see ASN1Path#ASN1Path(String, BigInteger, int, ASN1Path, Class,ASN1PathType)
   * @see Hex#parseBigInteger(String)
   * @see ASN1PathType#NO_INFORMATION
   */
  protected ASN1Path(String name, String tagHexString, int index, ASN1Path parent)
  {
    this(name, Hex.parse(AssertUtil.notNullOrEmpty(tagHexString, STRING_TAG_HEX_STRING)), index, parent, null,
         ASN1PathType.NO_INFORMATION);
  }

  /**
   * Constructor.
   *
   * @param name name, <code>null</code> or empty String permitted
   * @param tag tag of child element, <code>null</code> not permitted, must specify a valid tag
   * @param index index of child element, only zero or positive value permitted
   * @param parent optional parent path element
   * @param encoderClass Class of {@link ASN1Encoder} for creating ASN1. object with support convenience
   *          methods to access contents of ASN.1, <code>null</code> permitted, any real Class must possess an
   *          empty, accessible Constructor to create an instance, otherwise an
   *          {@link IllegalArgumentException} is thrown
   * @param type of ASN1Path - indicates different kind of child and importance for validity checks, type not
   *          permitted as <code>null</code>
   * @throws IllegalArgumentException if Class of {@link ASN1Encoder} does not possess an empty constructor
   *           for initialization or if arguments not valid
   * @see ASN1Path#ASN1Path(String, BigInteger, int, Filter, ASN1Path, Class, ASN1PathType)
   */
  protected ASN1Path(String name,
                     BigInteger tag,
                     int index,
                     ASN1Path parent,
                     Class<? extends ASN1Encoder> encoderClass,
                     ASN1PathType type)
  {
    this(name, AssertUtil.notNullReturn(tag, STRING_TAG), index, null, parent, encoderClass,
         AssertUtil.notNullReturn(type, STRING_TYPE));
  }

  /**
   * Constructor.
   *
   * @param name name, <code>null</code> or empty String permitted
   * @param tagByte tag byte of child element, must specify a valid tag
   * @param index index of child element, only zero or positive value permitted
   * @param parent optional parent path element
   * @param encoderClass Class of {@link ASN1Encoder} for creating ASN1. object with support convenience
   *          methods to access contents of ASN.1, <code>null</code> permitted, any real Class must possess an
   *          empty, accessible Constructor to create an instance, otherwise an
   *          {@link IllegalArgumentException} is thrown
   * @throws IllegalArgumentException if Class of {@link ASN1Encoder} does not possess an empty constructor
   *           for initialization or if arguments not valid
   * @see ASN1Path#ASN1Path(String, byte[], int, ASN1Path, Class, ASN1PathType)
   * @see ASN1PathType#NO_INFORMATION
   */
  protected ASN1Path(String name,
                     byte tagByte,
                     int index,
                     ASN1Path parent,
                     Class<? extends ASN1Encoder> encoderClass)
  {
    this(name, new byte[]{tagByte}, index, parent, encoderClass, ASN1PathType.NO_INFORMATION);
  }

  /**
   * Constructor.
   *
   * @param name name, <code>null</code> or empty String permitted
   * @param tagBytes tag bytes of child element, <code>null</code> or empty array not permitted, must specify
   *          a valid tag
   * @param index index of child element, only zero or positive value permitted
   * @param parent optional parent path element
   * @param encoderClass Class of {@link ASN1Encoder} for creating ASN1. object with support convenience
   *          methods to access contents of ASN.1, <code>null</code> permitted, any real Class must possess an
   *          empty, accessible Constructor to create an instance, otherwise an
   *          {@link IllegalArgumentException} is thrown
   * @throws IllegalArgumentException if Class of {@link ASN1Encoder} does not possess an empty constructor
   *           for initialization or if arguments not valid
   * @see ASN1Path#ASN1Path(String, BigInteger, int, ASN1Path, Class, ASN1PathType)
   * @see ASN1PathType#NO_INFORMATION
   */
  protected ASN1Path(String name,
                     byte[] tagBytes,
                     int index,
                     ASN1Path parent,
                     Class<? extends ASN1Encoder> encoderClass)
  {
    this(name, new BigInteger(ASN1Util.checkTagBytes(tagBytes)), index, parent, encoderClass,
         ASN1PathType.NO_INFORMATION);
  }

  /**
   * Constructor.
   *
   * @param name name, <code>null</code> or empty String permitted
   * @param tagBytes tag bytes of child element, <code>null</code> or empty array not permitted, must specify
   *          a valid tag
   * @param index index of child element, only zero or positive value permitted
   * @param parent optional parent path element
   * @param encoderClass Class of {@link ASN1Encoder} for creating ASN1. object with support convenience
   *          methods to access contents of ASN.1, <code>null</code> permitted, any real Class must possess an
   *          empty, accessible Constructor to create an instance, otherwise an
   *          {@link IllegalArgumentException} is thrown
   * @param type type of ASN1Path
   * @throws IllegalArgumentException if Class of {@link ASN1Encoder} does not possess an empty constructor
   *           for initialization or if arguments not valid
   * @see ASN1Path#ASN1Path(String, BigInteger, int, ASN1Path, Class, ASN1PathType)
   */
  private ASN1Path(String name,
                   byte[] tagBytes,
                   int index,
                   ASN1Path parent,
                   Class<? extends ASN1Encoder> encoderClass,
                   ASN1PathType type)
  {
    this(name, new BigInteger(ASN1Util.checkTagBytes(tagBytes)), index, parent, encoderClass,
         AssertUtil.notNullReturn(type, STRING_TYPE));
  }

  /**
   * Constructor.
   *
   * @param name name, <code>null</code> or empty String permitted
   * @param tagHexString tag of child element as Hex-String, <code>null</code> or empty String not permitted,
   *          must specify a valid tag
   * @param index index of child element, only zero or positive value permitted
   * @param parent optional parent path element
   * @param encoderClass Class of {@link ASN1Encoder} for creating ASN1. object with support convenience
   *          methods to access contents of ASN.1, <code>null</code> permitted, any real Class must possess an
   *          empty, accessible Constructor to create an instance, otherwise an
   *          {@link IllegalArgumentException} is thrown
   * @throws IllegalArgumentException if Class of {@link ASN1Encoder} does not possess an empty constructor
   *           for initialization or if arguments not valid
   * @see ASN1Path#ASN1Path(String, BigInteger, int, ASN1Path, Class, ASN1PathType)
   * @see Hex#parseBigInteger(String)
   * @see ASN1PathType#NO_INFORMATION
   */
  protected ASN1Path(String name,
                     String tagHexString,
                     int index,
                     ASN1Path parent,
                     Class<? extends ASN1Encoder> encoderClass)
  {
    this(name, Hex.parse(AssertUtil.notNullOrEmpty(tagHexString, STRING_TAG_HEX_STRING)), index, parent,
         encoderClass, ASN1PathType.NO_INFORMATION);
  }

  /**
   * Constructor.
   *
   * @param name name, <code>null</code> or empty String permitted
   * @param tag tag of child element, <code>null</code> not permitted, must specify a valid tag
   * @param filter filter for element, <code>null</code> not permitted, filter class of filter only permitted
   *          as {@link ASN1}
   * @param parent optional parent path element
   * @param encoderClass Class of {@link ASN1Encoder} for creating ASN1. object with support convenience
   *          methods to access contents of ASN.1, <code>null</code> permitted, any real Class must possess an
   *          empty, accessible Constructor to create an instance, otherwise an
   *          {@link IllegalArgumentException} is thrown
   * @param type of ASN1Path - indicates different kind of child and importance for validity checks, type not
   *          permitted as <code>null</code>
   * @throws IllegalArgumentException if Class of {@link ASN1Encoder} does not possess an empty constructor
   *           for initialization or arguments not valid
   * @see ASN1Path#ASN1Path(String, BigInteger, int, Filter, ASN1Path, Class, ASN1PathType)
   */
  private ASN1Path(String name,
                   BigInteger tag,
                   Filter<ASN1> filter,
                   ASN1Path parent,
                   Class<? extends ASN1Encoder> encoderClass,
                   ASN1PathType type)
  {
    this(name, AssertUtil.notNullReturn(tag, STRING_TAG), NO_INDEX,
         AssertUtil.notNullReturn(filter, STRING_FILTER), parent, encoderClass,
         AssertUtil.notNullReturn(type, STRING_TYPE));
  }

  /**
   * Constructor.
   *
   * @param name name, <code>null</code> or empty String permitted
   * @param tag tag of child element, <code>null</code> not permitted, must specify a valid tag
   * @param index index of child element, when filter specified always {@link #NO_INDEX}, otherwise index less
   *          than 0 not permitted
   * @param filter filter for element, <code>null</code> permitted if index is not {@link #NO_INDEX}, filter
   *          class of filter only permitted as {@link ASN1}
   * @param parent optional parent path element
   * @param encoderClass Class of {@link ASN1Encoder} for creating ASN1. object with support convenience
   *          methods to access contents of ASN.1, <code>null</code> permitted, any real Class must possess an
   *          empty, accessible Constructor to create an instance, otherwise an
   *          {@link IllegalArgumentException} is thrown
   * @param type of ASN1Path - indicates different kind of child and importance for validity checks, type not
   *          permitted as <code>null</code>
   * @throws IllegalArgumentException if Class of {@link ASN1Encoder} does not possess an empty constructor
   *           for initialization or arguments not valid
   */
  private ASN1Path(String name,
                   BigInteger tag,
                   int index,
                   Filter<ASN1> filter,
                   ASN1Path parent,
                   Class<? extends ASN1Encoder> encoderClass,
                   ASN1PathType type)
  {
    super();
    AssertUtil.notNull(tag, STRING_TAG);
    ASN1Util.checkTagBytes(tag.toByteArray());
    if (filter != null && index != NO_INDEX)
    {
      throw new IllegalArgumentException("filter specified, index only permitted as -1");
    }
    else if (filter == null)
    {
      AssertUtil.zeroOrPositive(index, "index");
    }
    else
    {
      AssertUtil.equals(ASN1.class, filter.getFilterClass(), "filter class");
    }
    if (encoderClass != null)
    {
      try
      {
        encoderClass.getConstructor();
        encoderClass.newInstance();
      }
      catch (SecurityException e)
      {
        throw new IllegalArgumentException("Class of encoder not permitted, expected empty constructor does not exist or not accessible",
                                           e);
      }
      catch (NoSuchMethodException e)
      {
        throw new IllegalArgumentException("Class of encoder not permitted, expected empty constructor does not exist",
                                           e);
      }
      catch (InstantiationException e)
      {
        throw new IllegalArgumentException("instance of encoder Class can not be instantiated", e);
      }
      catch (IllegalAccessException e)
      {
        throw new IllegalArgumentException("Class of encoder not permitted, expected empty constructor does not accessible",
                                           e);
      }
      catch (Exception e)
      {
        throw new IllegalArgumentException("Class of encoder not permitted, instantiation of encoder instance failed: "
                                           + e.getMessage(), e);

      }
    }
    AssertUtil.notNull(type, STRING_TYPE);
    this.name = name;
    this.tag = tag;
    this.filter = filter;
    this.index = index;
    this.parent = parent;
    this.encoderClass = encoderClass;
    this.type = type;
  }

  /**
   * Constructor.
   *
   * @param name name, <code>null</code> or empty String permitted
   * @param tagByte tag byte of child element, must specify a valid tag
   * @param filter filter for element, <code>null</code> not permitted, filter class of filter only permitted
   *          as {@link ASN1}
   * @param parent optional parent path element
   * @param encoderClass Class of {@link ASN1Encoder} for creating ASN1. object with support convenience
   *          methods to access contents of ASN.1, <code>null</code> permitted, any real Class must possess an
   *          empty, accessible Constructor to create an instance, otherwise an
   *          {@link IllegalArgumentException} is thrown
   * @throws IllegalArgumentException if Class of {@link ASN1Encoder} does not possess an empty constructor
   *           for initialization
   * @see ASN1Path#ASN1Path(String, byte[], Filter, ASN1Path, Class, ASN1PathType)
   */
  protected ASN1Path(String name,
                     byte tagByte,
                     Filter<ASN1> filter,
                     ASN1Path parent,
                     Class<? extends ASN1Encoder> encoderClass)
  {
    this(name, new byte[]{tagByte}, filter, parent, encoderClass, ASN1PathType.NO_INFORMATION);
  }

  /**
   * Constructor.
   *
   * @param name name, <code>null</code> or empty String permitted
   * @param tagBytes tag bytes of child element, <code>null</code> or empty array not permitted, must specify
   *          a valid tag
   * @param filter filter for element, <code>null</code> not permitted, filter class of filter only permitted
   *          as {@link ASN1}
   * @param parent optional parent path element
   * @param encoderClass Class of {@link ASN1Encoder} for creating ASN1. object with support convenience
   *          methods to access contents of ASN.1, <code>null</code> permitted, any real Class must possess an
   *          empty, accessible Constructor to create an instance, otherwise an
   *          {@link IllegalArgumentException} is thrown
   * @param type type of ASN1Path
   * @throws IllegalArgumentException if Class of {@link ASN1Encoder} does not possess an empty constructor
   *           for initialization
   * @see ASN1Path#ASN1Path(String, BigInteger, Filter, ASN1Path, Class, ASN1PathType)
   */
  private ASN1Path(String name,
                   byte[] tagBytes,
                   Filter<ASN1> filter,
                   ASN1Path parent,
                   Class<? extends ASN1Encoder> encoderClass,
                   ASN1PathType type)
  {
    this(name, new BigInteger(ASN1Util.checkTagBytes(tagBytes)), filter, parent, encoderClass, type);
  }

  /**
   * Gets parent path element.
   *
   * @return parent path element, <code>null</code> for root path
   */
  public ASN1Path getParent()
  {
    return parent;
  }

  /**
   * Gets name of path.
   *
   * @return name
   */
  public String getName()
  {
    return name;
  }

  /**
   * Gets tag of child element.
   *
   * @return tag
   */
  public BigInteger getTag()
  {
    return tag;
  }

  /**
   * Gets index of child element, if multiple child elements with same tag exists, e.g. in a sequence.
   *
   * @return index of child element
   */
  public int getIndex()
  {
    return index;
  }

  /** {@inheritDoc} */
  @Override
  public String toString()
  {
    return this.getName() + "(Tag: 0x" + Hex.hexify(this.tag.toByteArray()) + ", Index: " + this.index
           + ", Parent: " + (this.parent != null ? this.parent.name : "no parent") + ")";
  }

  // instantiate an instance for decoding
  private ASN1Encoder getEncoder()
  {
    ASN1Encoder result = null;
    if (this.encoderClass != null)
    {
      try
      {
        result = this.encoderClass.newInstance();
      }
      catch (InstantiationException e)
      {
        // checked before
        LOG.debug("instantiating failed: " + e.getMessage());
      }
      catch (IllegalAccessException e)
      {
        // checked before
        LOG.debug("instantiating failed, constructor not accessible: " + e.getMessage());
      }
    }
    return result;
  }

  /**
   * Decodes/Initializes encodable from ASN.1 object.
   *
   * @param asn1 ASN.1 object, <code>null</code> not permitted
   * @return encodable
   * @throws IllegalArgumentException if ASN.1 object <code>null</code>
   * @see ASN1Encoder#decode(ASN1)
   */
  final ASN1 getASN1(ASN1 asn1)
  {
    AssertUtil.notNull(asn1, "asn1");
    ASN1Encoder encoder = getEncoder();
    if (encoder != null)
    {
      return encoder.decode(asn1);
    }
    return null;
  }

  /**
   * Gets Class of {@link ASN1Encoder} for simple access of ASN.1 content.
   *
   * @return the encodableClass, maybe <code>null</code>
   */
  public Class<? extends ASN1Encoder> getEncoderClass()
  {
    return encoderClass;
  }

  /**
   * Gets type.
   *
   * @return type
   */
  public ASN1PathType getType()
  {
    return this.type;
  }

}

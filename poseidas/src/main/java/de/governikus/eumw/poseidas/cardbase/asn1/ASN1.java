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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import de.governikus.eumw.poseidas.cardbase.ArrayUtil;
import de.governikus.eumw.poseidas.cardbase.AssertUtil;
import de.governikus.eumw.poseidas.cardbase.ByteUtil;
import de.governikus.eumw.poseidas.cardbase.CollectionUtil;
import de.governikus.eumw.poseidas.cardbase.Filter;
import de.governikus.eumw.poseidas.cardbase.Hex;
import de.governikus.eumw.poseidas.cardbase.constants.Constants;


/**
 * Implementation of ASN.1.
 * <p>
 * Notice: full support of ASN.1 encoding rules for tags with multiple bytes.
 * </p>
 *
 * @author Jens Wothe, jw@bos-bremen.de
 */
public class ASN1
{

  /**
   * {@link Logger} instance.
   */
  private static final Log LOG = LogFactory.getLog(ASN1.class.getName());

  /**
   * Constant of default stream closing.
   *
   * @see ASN1#ASN1(InputStream, boolean)
   */
  private static final boolean DEFAULT_CLOSE = false;

  private boolean immutable = false;

  private boolean changeEnabled = true;

  /**
   * Sets ASN.1 to immutable (not changeable).
   * <p>
   * Note: ignored by already immutable ASN.1, otherwise all children have to be immutable too.
   * </p>
   */
  private final synchronized void setImmutable()
  {
    if (immutable)
    {
      return;
    }
    updateInt();
    getEncoded();
    try
    {
      List<ASN1> childList = getChildElementListInt();
      if (!CollectionUtil.isNullOrEmpty(childList))
      {
        for ( ASN1 child : childList )
        {
          child.setChangeEnabled(false);
          child.setImmutable();
        }
      }
    }
    catch (IOException e)
    {
      LOG.debug("setting immutable internally failed: " + e.getMessage());
    }
    this.immutable = true;
    this.changeEnabled = false;
  }


  /**
   * Checks ASN.1 is immutable (no changes possible).
   *
   * @return <code>true</code> for unchangeable/immutable ASN.1
   */
  public final synchronized boolean isImmutable()
  {
    return immutable;
  }

  /**
   * Bytes of Description and Tag - including ASN.1 bit coded informations about class and content.
   */
  private byte[] dTagBytes = null;

  /**
   * Bytes of length.
   */
  private byte[] lengthBytes = null;

  /**
   * Bytes of value.
   */
  private byte[] valueBytes = null;

  /**
   * Child elements of this instance.
   */
  private List<ASN1> childElementList = null;

  /**
   * Constructor of immutable ASN.1.
   *
   * @param dTagBytes bytes of Description and Tag - including ASN.1 bit coded informations about class and
   *          content, <code>null</code> or empty array not permitted
   * @param lengthBytes bytes of length, <code>null</code> or empty array not permitted
   * @param valueBytes bytes of value, <code>null</code> or empty array permitted
   * @param immutable <code>true</code> for immutable ASN.1
   * @throws IllegalArgumentException if byte arrays does specify a valid ASN.1
   */
  protected ASN1(byte[] dTagBytes, byte[] lengthBytes, byte[] valueBytes, boolean immutable)
  {
    this(dTagBytes, lengthBytes, valueBytes);
    if (immutable)
    {
      setImmutable();
    }
  }

  /**
   * Constructor.
   *
   * @param dTagBytes bytes of Description and Tag - including ASN.1 bit coded informations about class and
   *          content, <code>null</code> or empty array not permitted
   * @param lengthBytes bytes of length, <code>null</code> or empty array not permitted
   * @param valueBytes bytes of value, <code>null</code> or empty array permitted
   * @throws IllegalArgumentException if byte arrays does specify a valid ASN.1
   */
  private ASN1(byte[] dTagBytes, byte[] lengthBytes, byte[] valueBytes)
  {
    super();
    ASN1Util.checkTagBytes(dTagBytes);
    AssertUtil.notNullOrEmpty(lengthBytes, "length bytes");
    this.dTagBytes = ByteUtil.copy(dTagBytes);
    this.lengthBytes = ByteUtil.copy(lengthBytes);
    this.valueBytes = ByteUtil.copy(valueBytes);
    initValueBytes();
    if (!ASN1Constants.LENGTH_UNDETERMINED.equals(getLength()))
    {
      AssertUtil.equals(getLength().longValue(), this.valueBytes.length, "length and length of value");
    }
    updateInt();
  }




  private synchronized void initValueBytes()
  {
    if (this.valueBytes == null)
    {
      this.valueBytes = Constants.EMPTY_PRIMITIVE_BYTE_ARRAY;
    }
  }

  /**
   * Copy-Constructor.
   *
   * @param asn1 to be copied ASN.1, <code>null</code> not permitted
   * @throws IllegalArgumentException if asn1 is <code>null</code> or bytes of tag, length and value does not
   *           specify a valid ASN.1
   * @see ASN1#ASN1(byte[], byte[], byte[])
   */
  public ASN1(ASN1 asn1)
  {
    this(AssertUtil.notNullReturn(asn1, "asn1").getDTagBytes(), asn1.getLengthBytes(), asn1.getValue());
  }

  /**
   * Constructor.
   *
   * @param tag simple tag without further ASN.1 informations, null
   * @param valueBytes bytes of value
   * @see ASN1#ASN1(byte[], byte[])
   */
  public ASN1(int tag, byte[] valueBytes)
  {
    this(BigInteger.valueOf(tag).toByteArray(), valueBytes);
  }

  /**
   * Constructor.
   *
   * @param tag simple tag without further ASN.1 informations, null
   * @param valueBytes bytes of value
   * @see ASN1#ASN1(byte[], byte[])
   */
  public ASN1(byte tag, byte[] valueBytes)
  {
    this(new byte[]{tag}, valueBytes);
  }

  /**
   * Constructor.
   *
   * @param dTagBytes bytes of Description and Tag - including ASN.1 bit coded informations about class and
   *          content, <code>null</code> or empty array not permitted
   * @param valueBytes value bytes
   * @throws IllegalArgumentException if dTagBytes <code>null</code> or empty
   */
  public ASN1(byte[] dTagBytes, byte[] valueBytes)
  {
    super();
    AssertUtil.notNullOrEmpty(dTagBytes, "tag bytes");
    byte[] tmpDTagBytes = dTagBytes;
    if (tmpDTagBytes.length > 1)
    {
      tmpDTagBytes = ByteUtil.removeLeadingZero(tmpDTagBytes);
    }
    ASN1Util.checkTagBytes(tmpDTagBytes);
    this.dTagBytes = ByteUtil.copy(tmpDTagBytes);
    this.valueBytes = ByteUtil.copy(valueBytes);
    initValueBytes();
    this.lengthBytes = ASN1Util.getLengthBytes(this.valueBytes);
    if ((tmpDTagBytes.length > 1 || (tmpDTagBytes.length == 1 && tmpDTagBytes[0] != 00))
        && !ArrayUtil.isNullOrEmpty(valueBytes))
    {
      updateInt();
    }
  }


  /**
   * Constructor.
   *
   * @param bytes bytes of ASN.1, <code>null</code> or empty not permitted
   * @throws IllegalArgumentException if bytes <code>null</code> or empty
   * @throws IOException if reading of stream fails
   * @see ASN1#ASN1(InputStream, boolean)
   */
  public ASN1(byte[] bytes) throws IOException
  {
    this(new ByteArrayInputStream(AssertUtil.notNullOrEmpty(bytes, "bytes")), true);
  }

  /**
   * Constructor.
   *
   * @param stream stream with ASN.1 bytes, <code>null</code> not permitted
   * @throws IllegalArgumentException if byte stream does not contain a valid ASN.1 or <code>null</code>
   * @throws IOException if reading of stream fails
   * @see ASN1#ASN1(InputStream, boolean)
   */
  public ASN1(InputStream stream) throws IOException
  {
    this(stream, DEFAULT_CLOSE);
  }

  /**
   * Constructor.
   *
   * @param stream stream with ASN.1 bytes, <code>null</code> not permitted
   * @param close <code>true</code>, if stream is to be closed after reading
   * @throws IllegalArgumentException if byte stream does not contain a valid ASN.1 or <code>null</code>
   * @throws IOException if reading of stream fails
   * @see ASN1Util#getDTagBytes(InputStream)
   * @see ASN1Util#getBytesOfLength(InputStream)
   * @see ASN1Util#getBytesOfValue(byte[], byte[], InputStream)
   * @see ASN1Util#toLength(byte[])
   */
  ASN1(InputStream stream, boolean close) throws IOException
  {
    super();
    try
    {
      AssertUtil.notNull(stream, "stream");
      this.dTagBytes = ASN1Util.checkTagBytes(ASN1Util.getDTagBytes(stream));
      this.lengthBytes = ASN1Util.getBytesOfLength(stream);
      this.valueBytes = ASN1Util.getBytesOfValue(this.dTagBytes, ASN1Util.toLength(this.lengthBytes), stream);
    }
    finally
    {
      if (stream != null && close)
      {
        stream.close();
      }
    }
  }

  /**
   * Checks ASN1. is universal.
   *
   * @return <code>true</code>, if universal
   * @see ASN1Util#isUniversal(byte[])
   */
  public synchronized boolean isUniversal()
  {
    return ASN1Util.isUniversal(this.dTagBytes);
  }

  /**
   * Checks ASN.1 is application.
   *
   * @return <code>true</code>, if application
   * @see ASN1Util#isApplication(byte[])
   */
  public synchronized boolean isApplication()
  {
    return ASN1Util.isApplication(this.dTagBytes);
  }

  /**
   * Checks ASN.1 is context specific.
   *
   * @return <code>true</code>, if specific
   * @see ASN1Util#isContextSpecific(byte[])
   */
  public synchronized boolean isContextSpecific()
  {
    return ASN1Util.isContextSpecific(this.dTagBytes);
  }

  /**
   * Checks ASN.1 is private.
   *
   * @return <code>true</code>, if private
   * @see ASN1Util#isPrivate(byte[])
   */
  public synchronized boolean isPrivate()
  {
    return ASN1Util.isPrivate(this.dTagBytes);
  }

  /**
   * Checks ASN.1 is sequence.
   *
   * @return <code>true</code>, if sequence
   * @see ASN1Util#isSequence(byte[])
   */
  public synchronized boolean isSequence()
  {
    return ASN1Util.isSequence(this.dTagBytes);
  }

  /**
   * Checks ASN.1 is set.
   *
   * @return <code>true</code>, if set
   * @see ASN1Util#isSet(byte[])
   */
  public synchronized boolean isSet()
  {
    return ASN1Util.isSet(this.dTagBytes);
  }

  /**
   * Checks ASN.1 is primitive.
   *
   * @return <code>true</code>, if primitive
   * @see ASN1Util#isPrimitive(byte[])
   */
  public synchronized boolean isPrimitive()
  {
    return ASN1Util.isPrimitive(this.dTagBytes);
  }

  /**
   * Checks ASN.1. is constructed.
   *
   * @return <code>true</code>, if constructed
   * @see ASN1Util#isConstructed(byte[])
   */
  public synchronized boolean isConstructed()
  {
    return !ASN1Util.isPrimitive(this.dTagBytes);
  }

  /**
   * Gets Description and Tag - including ASN.1 bit coded informations about class and content.
   *
   * @return Description and Tag
   */
  public synchronized BigInteger getDTag()
  {
    return new BigInteger(this.dTagBytes);
  }

  /**
   * Gets Description and Tag as bytes - including ASN.1 bit coded informations about class and content.
   *
   * @return Description and Tag bytes
   */
  public synchronized byte[] getDTagBytes()
  {
    return ByteUtil.copy(this.dTagBytes);
  }

  /**
   * Gets Tag.
   *
   * @return Tag
   */
  public synchronized BigInteger getTag()
  {
    return ASN1Util.extractTag(this.dTagBytes);
  }

  /**
   * Gets length.
   *
   * @return length
   */
  public final synchronized BigInteger getLength()
  {
    return ASN1Util.toLength(this.lengthBytes);
  }

  /**
   * Gets length bytes.
   *
   * @return length bytes
   */
  public synchronized byte[] getLengthBytes()
  {
    return ByteUtil.copy(this.lengthBytes);
  }

  /**
   * Gets value bytes.
   *
   * @return value bytes
   */
  public synchronized byte[] getValue()
  {
    return ByteUtil.copy(this.valueBytes);
  }

  /**
   * Gets size as length of encoded byte[]-array representation.
   *
   * @return size
   */
  private synchronized BigInteger size()
  {
    int l = this.dTagBytes.length + this.lengthBytes.length;
    if (this.getLength() == ASN1Constants.LENGTH_UNDETERMINED)
    {
      l += ASN1Constants.EOC_ASN1.getEncoded().length;
    }
    if (this.valueBytes != null)
    {
      l += this.valueBytes.length;
    }
    return BigInteger.valueOf(l);
  }

  /**
   * Gets child elements.
   *
   * @return child elements
   * @throws IOException if getting elements fails
   * @see ASN1Util#getChildElements(ASN1)
   */
  public ASN1[] getChildElements() throws IOException
  {
    List<ASN1> childList = getChildElementList();
    return CollectionUtil.isNullOrEmpty(childList) ? new ASN1[0]
      : childList.toArray(new ASN1[childList.size()]);
  }

  /**
   * Adds list of child elements.
   *
   * @param childList list of child elements to be added
   * @param root optional root element to indicate changes to whole structure
   * @throws IOException if fails
   * @throws IllegalStateException if changing disabled
   * @throws UnsupportedOperationException if not supported (at least for all ASN.1 types that does not
   *           possess any child)
   */
  public final synchronized void addChildElements(List<ASN1> childList, ASN1 root) throws IOException
  {
    checkChangeEnabled();
    checkExtendedChildOperationAvailability();
    if (CollectionUtil.isNullOrEmpty(childList))
    {
      return;
    }
    List<ASN1> currentChildList = getChildElementListInt();
    if (!CollectionUtil.isNull(currentChildList))
    {
      for ( ASN1 child : childList )
      {
        if (child != null)
        {
          currentChildList.add(child);
          setChanged(root);
        }
      }

    }
  }

  /**
   * Adds one child element.
   *
   * @param child child, <code>null</code> permitted and ignored
   * @param root optional root element to indicate changes to whole structure
   * @throws IOException if fails
   * @throws IllegalStateException if changing disabled
   * @throws UnsupportedOperationException if not supported (at least for all ASN.1 types that does not
   *           possess any child)
   */
  public final synchronized void addChildElement(ASN1 child, ASN1 root) throws IOException
  {
    checkExtendedChildOperationAvailability();
    checkChangeEnabled();
    if (child == null)
    {
      return;
    }
    List<ASN1> childList = getChildElementListInt();
    if (!CollectionUtil.isNull(childList))
    {
      childList.add(child);
      setChanged(root);
    }
  }

  // checks ASN.1 is a sequence or other kind that supports child adding, etc.
  private void checkExtendedChildOperationAvailability()
  {
    if (!isSequence() && !isSet() && !isConstructed())
    {
      throw new UnsupportedOperationException("not a sequence or set, no functionality to add or remove any child element");
    }
  }

  /**
   * Gets count of child elements.
   *
   * @return count of child elements
   * @throws IOException if fails
   */
  public final synchronized int getChildElementCount() throws IOException
  {

    List<ASN1> childList = getChildElementListInt();
    return CollectionUtil.isNullOrEmpty(childList) ? 0 : childList.size();
  }

  /**
   * Replaces one child element against another.
   *
   * @param oldChild old child to be replaced by new child, <code>null</code> not permitted
   * @param newChild new child replacing old, <code>null</code> not permitted
   * @param root optional root element to indicate changes to whole structure
   * @throws IOException if fails
   * @throws IllegalStateException if changing disabled
   * @throws IllegalArgumentException if old or new child element is <code>null</code>
   * @throws UnsupportedOperationException if not supported (at least for all ASN.1 types that does not
   *           possess any child)
   */
  public final synchronized void replaceChildElement(ASN1 oldChild, ASN1 newChild, ASN1 root)
    throws IOException
  {
    checkChangeEnabled();
    checkExtendedChildOperationAvailability();
    if (oldChild == null)
    {
      throw new IllegalArgumentException("old child is null, use addChildElement for adding");
    }
    if (newChild == null)
    {
      throw new IllegalArgumentException("new child is null, use removeChildElement for adding");
    }
    List<ASN1> childList = getChildElementListInt();
    if (!CollectionUtil.isNullOrEmpty(childList) && childList.contains(oldChild))
    {
      childList.set(childList.indexOf(oldChild), newChild);
      setChanged(root);
    }
  }

  /**
   * Removes on child element.
   *
   * @param child child element to be removed, <code>null</code> permitted, if not found ignored, otherwise
   *          removed
   * @param root optional root element to indicate changes to whole structure
   * @throws IOException if fails
   * @throws IllegalStateException if changing disabled
   * @throws UnsupportedOperationException if not supported (at least for all ASN.1 types that does not
   *           possess any child)
   */
  public final synchronized void removeChildElement(ASN1 child, ASN1 root) throws IOException
  {
    checkChangeEnabled();
    checkExtendedChildOperationAvailability();
    List<ASN1> childList = getChildElementListInt();
    if (!CollectionUtil.isNullOrEmpty(childList) && childList.contains(child))
    {
      childList.remove(child);
      setChanged(root);
    }
  }

  /**
   * Gets child element list (internal, modifiable list).
   *
   * @return child elements
   * @throws IOException if getting elements fails
   * @see ASN1Util#getChildElements(ASN1)
   */
  private final synchronized List<ASN1> getChildElementListInt() throws IOException
  {
    if (this.valueBytes == null)
    {
      return this.childElementList;
    }
    if (this.childElementList == null || this.childElementList.isEmpty())
    {
      this.childElementList = ASN1Util.getChildElementList(this);
    }
    return this.childElementList;
  }

  /**
   * Gets child element list (unmodifiable).
   *
   * @return child elements
   * @throws IOException if getting elements fails
   * @see ASN1Util#getChildElements(ASN1)
   */
  public final List<ASN1> getChildElementList() throws IOException
  {
    return Collections.unmodifiableList(getChildElementListInt());
  }

  /**
   * Gets child elements with given tag.
   *
   * @param tag tag of child elements
   * @return child elements with tag
   * @throws IOException if getting elements fails
   * @see ASN1Util#filterByTag(ASN1[], int)
   */
  public ASN1[] getChildElementsByTag(int tag) throws IOException
  {
    return ASN1Util.filterByTag(this.getChildElements(), tag);
  }

  /**
   * Gets child elements with given tag.
   *
   * @param tag tag of child elements
   * @return child elements with tag
   * @throws IOException if getting elements fails
   * @see ASN1Util#filterByTagOfDTag(ASN1[], BigInteger)
   */
  public ASN1[] getChildElementsByTag(BigInteger tag) throws IOException
  {
    return ASN1Util.filterByTagOfDTag(this.getChildElements(), tag);
  }

  /**
   * Gets child elements with given tag.
   *
   * @param dTag tag of child elements
   * @return child elements with tag
   * @throws IOException if getting elements fails
   * @see ASN1Util#filterByTag(ASN1[], Short)
   */
  private ASN1[] getChildElementsByDTag(BigInteger dTag) throws IOException
  {
    return ASN1Util.filterByDTag(this.getChildElements(), dTag);
  }

  /**
   * Gets child elements with given tag.
   *
   * @param dTagBytes tag descriptor bytes of child elements
   * @return child elements with tag
   * @throws IOException if getting elements fails
   * @see ASN1Util#filterByTag(ASN1[], Short)
   */
  public ASN1[] getChildElementsByDTagBytes(byte[] dTagBytes) throws IOException
  {
    return ASN1Util.filterByDTagBytes(this.getChildElements(), dTagBytes);
  }

  // field indicating internal changes - especially if child elements added or removed
  private boolean changed = false;

  /**
   * Set state of ASN.1.
   *
   * @param changed <code>true</code> for changed (forces recoding at {@link #getEncoded()}),
   *          <code>false</code> to avoid recoding, recommended any changes of child elements or value bytes
   *          must indicate content changes by calling with <code>true</code>
   * @throws IllegalStateException if changing disabled
   */
  private final synchronized void setChanged(boolean changed)
  {
    checkChangeEnabled();
    this.changed = changed;
    try
    {
      List<ASN1> childList = getChildElementListInt();
      if (!CollectionUtil.isNullOrEmpty(childList))
      {
        for ( ASN1 child : childList )
        {
          child.setChanged(changed);
        }
      }
    }
    catch (IOException e)
    {
      LOG.debug("setting changed state failed: " + e.getMessage());
    }
  }

  /**
   * Sets value bytes (enforce internal update and indication of changes if necessary).
   *
   * @param valueBytes new value bytes of this ASN.1
   * @param root optional root element to indicate changes to whole structure
   * @throws IllegalStateException if changing disabled
   * @see #update()
   */
  public final synchronized void setValueBytes(byte[] valueBytes, ASN1 root)
  {
    checkChangeEnabled();
    if (this.valueBytes == valueBytes)
    {
      return;
    }
    if (this.valueBytes == null || valueBytes == null || !Arrays.equals(this.valueBytes, valueBytes))
    {
      this.valueBytes = ByteUtil.copy(valueBytes);
      this.lengthBytes = ASN1Util.getLengthBytes(this.valueBytes);
      if (!CollectionUtil.isNullOrEmpty(this.childElementList))
      {
        this.childElementList.clear();
      }
      this.childElementList = null;
      getEncoded();
      try
      {
        getChildElementListInt();
      }
      catch (Exception e)
      {
        LOG.debug("setting values bytes failed: " + e.getMessage());
      }
      update();
      setChanged(root);
    }
  }

  private synchronized void setChanged(ASN1 root)
  {
    if (root != null)
    {
      root.setChanged(true);
      root.getEncoded();
    }
    else
    {
      this.setChanged(true);
      this.getEncoded();
    }
  }


  /**
   * Checks this ASN.1 or any nested child element is changed.
   *
   * @return <code>true</code> if changed, otherwise <code>false</code>
   */
  public final synchronized boolean isChanged()
  {
    boolean result = changed;
    if (!result)
    {
      List<ASN1> childList = null;
      try
      {
        childList = getChildElementList();
      }
      catch (IOException e)
      {
        if (LOG.isDebugEnabled())
        {
          LOG.debug("Failed to read child list: " + e.getMessage());
        }
        return false;
      }
      if (!CollectionUtil.isNullOrEmpty(this.childElementList))
      {
        for ( ASN1 child : childList )
        {
          result |= child.isChanged();
          if (result)
          {
            break;
          }
        }
      }
    }
    return result;
  }

  /**
   * Gets byte[]-array encoded representation.
   *
   * @return bytes
   */
  public synchronized byte[] getEncoded()
  {
    byte[] result = null;
    try (ByteArrayOutputStream baos = new ByteArrayOutputStream())
    {
      baos.write(this.dTagBytes);
      if (isChanged())
      {
        if (!CollectionUtil.isNullOrEmpty(this.childElementList))
        {
          ByteArrayOutputStream cbaos = new ByteArrayOutputStream();
          for ( ASN1 child : this.childElementList )
          {
            cbaos.write(child.getEncoded());
          }
          cbaos.flush();
          cbaos.close();
          this.valueBytes = cbaos.toByteArray();
          this.lengthBytes = ASN1Util.getLengthBytes(this.valueBytes);
          // use specialized method of instance to keep other instances of consistent
          update();
        }
        else
        {
          this.lengthBytes = ASN1Util.getLengthBytes(this.valueBytes);
        }
      }
      baos.write(this.lengthBytes);
      if (this.valueBytes != null && this.valueBytes.length > 0)
      {
        baos.write(this.valueBytes);
      }
      if (this.lengthBytes.length == 1 && this.lengthBytes[0] == ASN1Constants.LENGTH_UNDETERMINED_BYTE)
      {
        baos.write(ASN1Constants.EOC_ASN1.getEncoded());
      }
      this.changed = false;
      result = baos.toByteArray();
    }
    catch (IOException e)
    {
      LOG.debug("getting encoded failed: " + e.getMessage());
    }
    return result;
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public boolean equals(Object object)
  {
    if (!(object instanceof ASN1))
    {
      return false;
    }
    ASN1 friendlyASN1Value = (ASN1)object;
    return Arrays.equals(this.getEncoded(), friendlyASN1Value.getEncoded());
  }

  /**
   * Gets {@link Object#toString()} representation.
   *
   * @return default string representation
   */
  private String toStringClass()
  {
    String result = super.toString();
    result = this.getClass().getName() + result.substring(result.indexOf('@'));
    return result;
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public String toString()
  {
    return toString(ASN1Constants.FULL_FORMAT);
  }

  /**
   * Returns a string representation with reduced or full informations about this ASN.1.
   *
   * @param format format of String representation
   * @return String representation in given format
   * @see ASN1Constants#FULL_FORMAT
   * @see ASN1Constants#REDUCED_FORMAT
   */
  public String toString(boolean format)
  {
    return toString("", "", format);
  }

  /**
   * Returns a string representation with reduced or full informations about this ASN.1 using indents for
   * child elements.
   *
   * @param indent1 indent for String representation of this ASN.1
   * @param indent2 indent for String representation of child elements of this ASN.1
   * @param format format of String representation
   * @return String representation in given format
   * @see ASN1Util#appendBytes(StringBuilder, String, byte[])
   * @see ASN1Constants#FULL_FORMAT
   * @see ASN1Constants#REDUCED_FORMAT
   * @see Hex#hexify(byte[])
   */
  private String toString(String indent1, String indent2, boolean format)
  {
    StringBuilder buffer = new StringBuilder();
    buffer.append(indent1 + toStringClass());
    if (format == ASN1Constants.FULL_FORMAT)
    {
      buffer.append("\n" + indent1 + indent2 + "-    Tag:\n");
      ASN1Util.appendBytes(buffer, indent1 + indent2, ASN1Util.extractTag(this.dTagBytes).toByteArray());
      buffer.append("\n" + indent1 + indent2 + "-   DTag:\n");
      ASN1Util.appendBytes(buffer, indent1 + indent2, this.dTagBytes);
      buffer.append("\n" + indent1 + indent2 + "- Length:\n");
      ASN1Util.appendBytes(buffer, indent1 + indent2, this.lengthBytes);
      buffer.append("\n" + indent1 + indent2 + "-  Value:\n");
      for ( int i = 0 ; (i * 16) < this.valueBytes.length ; i++ )
      {
        ASN1Util.appendBytes(buffer,
                             indent1 + indent2,
                             ByteUtil.subbytes(this.valueBytes,
                                               i * 16,
                                               Math.min((i + 1) * 16, this.valueBytes.length)));
        buffer.append('\n');
      }
    }
    else
    {
      buffer.append("(Tag: 0x" + Hex.hexify(this.getTag()));
      buffer.append(", DTag: 0x" + Hex.hexify(this.getDTag()));
      buffer.append(", Length: " + this.getLength());
      buffer.append(", Encoded-Length: " + this.size());
      try
      {
        buffer.append(", ChildElements: " + getChildElements().length);
      }
      catch (IOException e)
      {
        LOG.debug("creating String failed: " + e.getMessage());
      }
      buffer.append(')');
    }
    return buffer.toString();
  }

  /**
   * Gets child element of ASN.1 by given path. Note: this method only works reliable if being called on an
   * {@link ASN1} which is root of the {@link ASN1Path} structure of which given <code>path</code> is element.
   *
   * @param path path to child element, <code>null</code> not permitted
   * @return child element of ASN.1 specified by path, uses subclass of {@link ASN1} if given in path object,
   *         <code>null</code>, if not found
   * @throws IOException if reading fails
   * @throws IllegalArgumentException if requested path <code>null</code>
   */
  public ASN1 getChildElementByPath(ASN1Path path) throws IOException
  {
    AssertUtil.notNull(path, "path");
    List<ASN1Path> partList = new ArrayList<>();
    ASN1Path rootPart = path;
    while (rootPart.getParent() != null)
    {
      partList.add(0, rootPart);
      rootPart = rootPart.getParent();
    }
    if (!this.getDTag().equals(rootPart.getTag()))
    {
      return null;
    }
    ASN1 tmp = this;
    for ( ASN1Path p : partList )
    {
      ASN1[] children = tmp.getChildElementsByDTag(p.getTag());
      if (children == null || children.length <= p.getIndex())
      {
        return null;
      }
      if (p.getFilter() == null)
      {
        tmp = children[p.getIndex()];
      }
      else
      {
        tmp = null;
        Filter<ASN1> filter = p.getFilter();
        for ( ASN1 element : children )
        {
          if (filter.accept(element))
          {
            tmp = element;
            break;
          }
        }
      }
      if (tmp == null)
      {
        return null;
      }
    }
    if (path.getEncoderClass() != null)
    {
      tmp = path.getASN1(tmp);
    }
    return tmp;
  }

  /**
   * Copies information of ASN.1 object without check.
   *
   * @param asn1 ASN.1 object to copy, <code>null</code> not permitted
   * @throws IllegalArgumentException if asn1 <code>null</code>
   * @throws IllegalStateException if changing disabled
   */
  protected synchronized void copy(ASN1 asn1)
  {
    checkChangeEnabled();
    AssertUtil.notNull(asn1, "ASN.1");
    this.dTagBytes = ByteUtil.copy(asn1.getDTagBytes());
    this.lengthBytes = ByteUtil.copy(asn1.getLengthBytes());
    this.valueBytes = ByteUtil.copy(asn1.getValue());
    this.childElementList = new ArrayList<>();
    updateInt();
  }

  private void updateInt()
  {
    try
    {
      // override for special implementations
      this.childElementList = getChildElementListInt();
    }
    catch (IOException ioe)
    {
      throw new IllegalArgumentException("copy failed: " + ioe.getMessage(), ioe);
    }
    // call detailed specialized update method anywhere
    update();
  }

  /**
   * Internal update method for any additional steps to be done if instance is copied.
   *
   * @see #copy(ASN1)
   * @throws IllegalStateException if ASN.1 not in state for update
   * @throws IllegalArgumentException if ASN.1 contains inconsistent or invalid data, other case is parsing of
   *           child elements fails
   */
  protected void update()
  {
    // implemented at derived classes to perform internal update steps
  }

  void checkChangeEnabled()
  {
    if (!changeEnabled)
    {
      throw new IllegalStateException("change not enabled");
    }
  }

  /**
   * Check changing ASN.1 is enabled.
   *
   * @return <code>true</code> for enabled, <code>false</code> if not
   */
  public final synchronized boolean isChangeEnabled()
  {
    return changeEnabled;
  }

  /**
   * Enables or disables changing of ASN.1.
   *
   * @param changeEnabled <code>true</code> for enabled, <code>false</code> for prevent from changes
   * @throws UnsupportedOperationException if ASN.1 is immutable
   */
  public final synchronized void setChangeEnabled(boolean changeEnabled)
  {
    if (this.immutable)
    {
      throw new UnsupportedOperationException("changing not supported for this immutable ASN.1");
    }
    this.changeEnabled = changeEnabled;
    try
    {
      List<ASN1> childList = getChildElementListInt();
      if (!CollectionUtil.isNullOrEmpty(childList))
      {
        for ( ASN1 child : childList )
        {
          child.setChangeEnabled(changeEnabled);
        }
      }
    }
    catch (IOException e)
    {
      LOG.debug("enable changes failed: " + e.getMessage());
    }
  }

  /** {@inheritDoc} */
  @Override
  public int hashCode()
  {
    return Arrays.hashCode(getEncoded());
  }


  protected Integer getInteger(ASN1Path path) throws IOException
  {
    ASN1Integer a = (ASN1Integer)this.getChildElementByPath(path);
    if (a == null)
    {
      return null;
    }
    return a.getInteger();
  }

  protected int getInt(ASN1Path path) throws IOException
  {
    return ((ASN1Integer)this.getChildElementByPath(path)).getInteger();
  }

  protected String getString(ASN1Path path) throws IOException
  {
    return new String(this.getChildElementByPath(path).getValue(), StandardCharsets.UTF_8);
  }

  protected String getStringNull(ASN1Path path) throws IOException
  {
    ASN1 sv = this.getChildElementByPath(path);
    if (sv == null)
    {
      return null;
    }
    return new String(sv.getValue(), StandardCharsets.UTF_8);
  }
}

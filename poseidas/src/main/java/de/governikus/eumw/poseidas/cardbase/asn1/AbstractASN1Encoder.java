/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardbase.asn1;

import java.io.IOException;
import java.io.InputStream;

import de.governikus.eumw.poseidas.cardbase.AssertUtil;


/**
 * Abstract encoder for ASN.1 structures as part of {@link ASN1Path}.
 *
 * @author Jens Wothe, jw@bos-bremen.de
 */
public class AbstractASN1Encoder extends ASN1 implements ASN1Encoder
{

  /**
   * Constructor.
   *
   * @param tag simple tag without further ASN.1 informations, null
   * @param valueBytes bytes of value
   * @see ASN1#ASN1(byte, byte[])
   */
  public AbstractASN1Encoder(byte tag, byte[] valueBytes)
  {
    super(tag, valueBytes);
  }

  /**
   * Constructor.
   *
   * @param bytes bytes of ASN.1
   * @throws IOException if reading of stream fails
   * @see ASN1#ASN1(byte[])
   */
  public AbstractASN1Encoder(byte[] bytes) throws IOException
  {
    super(bytes);
  }

  /**
   * Default encoder constructor.
   *
   * @see ASN1#ASN1(byte, byte[])
   */
  public AbstractASN1Encoder()
  {
    super(0, new byte[0]);
  }

  public AbstractASN1Encoder(byte[] dTagBytes, byte[] valueBytes)
  {
    super(dTagBytes, valueBytes);
  }

  public AbstractASN1Encoder(InputStream stream, boolean close) throws IOException
  {
    super(stream, close);
  }

  public AbstractASN1Encoder(InputStream stream) throws IOException
  {
    super(stream);
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public ASN1 decode(byte[] bytes) throws IOException
  {
    AssertUtil.notNullOrEmpty(bytes, "bytes");
    ASN1 asn1 = new ASN1(bytes);
    return this.decode(asn1);
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public ASN1 decode(ASN1 asn1)
  {
    checkChangeEnabled();
    AssertUtil.notNull(asn1, "ASN.1");
    if (!asn1.getClass().isAssignableFrom(this.getClass()))
    {
      throw new IllegalArgumentException("incompatible ASN1.object");
    }
    this.copy(asn1);
    return this;
  }
}

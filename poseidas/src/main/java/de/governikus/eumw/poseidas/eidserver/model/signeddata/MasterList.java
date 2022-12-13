/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.eidserver.model.signeddata;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;

import de.governikus.eumw.utils.key.SecurityProvider;


/**
 * MasterList container class for a CSCA Master List.
 *
 * @author Alexander Funk
 */
public class MasterList extends AbstractASN1List
{

  private static final Log LOGGER = LogFactory.getLog(MasterList.class.getName());

  private static final String OID_ICAO_MRTD_SECURITY = OID_ICAO + ".1" + ".1";

  private static final String OID_MASTER_LIST = OID_ICAO_MRTD_SECURITY + ".2";

  private List<X509Certificate> certificates;

  private CertificateFactory certFactory;

  /**
   * Generates a master list from a byte representation
   *
   * @param bytes the byte representation of the master list
   * @throws IllegalArgumentException if the master list is malformed or not parseable.
   */
  public MasterList(byte[] bytes)
  {
    super(bytes, OID_MASTER_LIST);

  }

  @Override
  public void parseList(ASN1Primitive object) throws IOException
  {
    check();
    // Get the octets
    ASN1Primitive obj = null;
    // Create a new input stream for bytes representing master list
    try (ASN1InputStream asn1 = new ASN1InputStream(object.getEncoded()))
    {
      obj = asn1.readObject();
    }
    ASN1OctetString dos = (ASN1OctetString)obj;
    byte[] octets = dos.getOctets();

    // New input stream to collect certificates
    try (ASN1InputStream asn1 = new ASN1InputStream(octets))
    {
      obj = asn1.readObject();
      if (obj instanceof ASN1Sequence)
      {
        ASN1Sequence sequence = (ASN1Sequence)obj;
        int sequenceSize = sequence.size();
        for ( int i = 0 ; i < sequenceSize ; i++ )
        {
          ASN1Encodable objectAt = sequence.getObjectAt(i);
          if (objectAt instanceof ASN1Set)
          {
            ASN1Set set = (ASN1Set)objectAt;
            int setSize = set.size();
            for ( int j = 0 ; j < setSize ; j++ )
            {
              ASN1Encodable setMember = set.getObjectAt(j);
              byte[] certBytes = setMember.toASN1Primitive().getEncoded();
              ByteArrayInputStream bais = new ByteArrayInputStream(certBytes);
              try
              {
                X509Certificate x509cert = (X509Certificate)certFactory.generateCertificate(bais);

                // Add certificate for master list
                certificates.add(x509cert);
                if (LOGGER.isTraceEnabled())
                {
                  LOGGER.trace("Adding certificate" + x509cert.toString());
                }
              }
              catch (CertificateException e)
              {
                throw new IOException("This is not a x509 certificate for factory '"
                                      + certFactory.getProvider() + "':" + setMember.toString(), e);
              }
            }
          }
        }
      }
    }
  }

  /**
   * Returns the trustworthy certificates that might be used to sign the travel document to check
   *
   * @return the list of X509Certificates
   */
  public List<X509Certificate> getCertificates()
  {
    try
    {
      check();
      return new LinkedList<>(certificates);
    }
    catch (IOException e)
    {
      LOGGER.warn("No certificates available or parseable: " + e);
      return new LinkedList<>();
    }
  }

  /**
   * Checks if list and factory are available
   *
   * @throws IOException if X509 certificate factory is not available
   */
  private void check() throws IOException
  {
    if (certificates == null)
    {
      certificates = new LinkedList<>();
    }

    if (certFactory == null)
    {
      String x509 = "X.509";
      try
      {
        certFactory = CertificateFactory.getInstance(x509, SecurityProvider.BOUNCY_CASTLE_PROVIDER);
      }
      catch (CertificateException e)
      {
        throw new IOException("Can not get certificate factory for : " + x509, e);
      }
    }
  }
}

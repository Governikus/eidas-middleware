/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.eidservice;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.spec.ECField;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import de.governikus.eumw.poseidas.cardbase.ByteUtil;
import de.governikus.eumw.poseidas.cardbase.asn1.ASN1;
import de.governikus.eumw.poseidas.cardbase.crypto.ec.ECMath;
import de.governikus.eumw.poseidas.cardserver.eac.crypto.impl.KeyHandlerEC;
import de.governikus.eumw.poseidas.eidserver.convenience.CAConnection;
import sun.security.x509.AlgorithmId;
import sun.security.x509.BasicConstraintsExtension;
import sun.security.x509.CertificateAlgorithmId;
import sun.security.x509.CertificateExtensions;
import sun.security.x509.CertificateIssuerName;
import sun.security.x509.CertificateSerialNumber;
import sun.security.x509.CertificateSubjectName;
import sun.security.x509.CertificateValidity;
import sun.security.x509.CertificateVersion;
import sun.security.x509.CertificateX509Key;
import sun.security.x509.KeyUsageExtension;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;


/**
 * Dummy implementation of CAConnection, generating the certificates locally.
 *
 * @author Arne Stahlbock, arne.stahlbock@governikus.com
 */
public class DummyCAConnection implements CAConnection
{

  private static final Log LOG = LogFactory.getLog(DummyCAConnection.class);

  /** {@inheritDoc} */
  @Override
  public List<byte[]> submitPublicKey(byte[] pubKeyBytes, String dn)
  {
    List<byte[]> resultList = new ArrayList<>(2);

    try
    {
      ASN1 params = new ASN1(pubKeyBytes);
      BigInteger primeModulus = new BigInteger(
                                               ByteUtil.addLeadingZero(params.getChildElementsByDTagBytes(new byte[]{(byte)0x81})[0].getValue()));
      BigInteger firstCoefficient = new BigInteger(
                                                   ByteUtil.addLeadingZero(params.getChildElementsByDTagBytes(new byte[]{(byte)0x82})[0].getValue()));
      BigInteger secondCoefficient = new BigInteger(
                                                    ByteUtil.addLeadingZero(params.getChildElementsByDTagBytes(new byte[]{(byte)0x83})[0].getValue()));
      byte[] pointBytes = params.getChildElementsByDTagBytes(new byte[]{(byte)0x84})[0].getValue();
      BigInteger orderOfBasePoint = new BigInteger(
                                                   ByteUtil.addLeadingZero(params.getChildElementsByDTagBytes(new byte[]{(byte)0x85})[0].getValue()));
      BigInteger cofactor;
      ASN1[] cofactorASN1 = params.getChildElementsByDTagBytes(new byte[]{(byte)0x87});
      if (cofactorASN1 != null && cofactorASN1.length == 1)
      {
        cofactor = new BigInteger(ByteUtil.addLeadingZero(cofactorASN1[0].getValue()));
      }
      else
      {
        cofactor = BigInteger.ONE;
      }
      ECField field = new ECFieldFp(primeModulus);
      EllipticCurve curve = new EllipticCurve(field, firstCoefficient, secondCoefficient);
      ECPoint point = ECMath.pointFromBytes(pointBytes, primeModulus.bitLength() / 8);
      ECParameterSpec spec = new ECParameterSpec(curve, point, orderOfBasePoint, cofactor.intValue());

      byte[] keyBytes = params.getChildElementsByDTagBytes(new byte[]{(byte)0x86})[0].getValue();
      PublicKey pubKey = new KeyHandlerEC(32).buildKeyFromBytes(spec, keyBytes);

      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
      keyPairGenerator.initialize(256, new SecureRandom());
      KeyPair keyPair = keyPairGenerator.generateKeyPair();

      resultList.add(generateCertificate(keyPair.getPrivate(),
                                         keyPair.getPublic(),
                                         "CN=Super Test Cert Issuer",
                                         "CN=Super Test Cert Issuer").getEncoded());
      resultList.add(generateCertificate(keyPair.getPrivate(),
                                         pubKey,
                                         "CN=Super Test Cert Issuer",
                                         dn == null ? "CN=unknown" : dn).getEncoded());
    }
    catch (IOException | GeneralSecurityException e)
    {
      LOG.error("can not generate certificate", e);
      resultList.add("Fehler".getBytes(StandardCharsets.UTF_8));
      resultList.add("Fehler".getBytes(StandardCharsets.UTF_8));
    }
    return resultList;
  }

  private static X509Certificate generateCertificate(PrivateKey privkey,
                                                     PublicKey pubkey,
                                                     String issuerDN,
                                                     String dn) throws GeneralSecurityException, IOException
  {
    boolean ca = issuerDN.equals(dn);

    X509CertInfo info = new X509CertInfo();
    Date from = new Date();
    Date to = new Date(from.getTime() + 100 * 86400000l);
    CertificateValidity interval = new CertificateValidity(from, to);
    BigInteger sn = new BigInteger(64, new SecureRandom());
    X500Name issuer = new X500Name(issuerDN);
    X500Name owner = new X500Name(dn);

    info.set(X509CertInfo.VALIDITY, interval);
    info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(sn));
    info.set(X509CertInfo.ISSUER, new CertificateIssuerName(issuer));
    info.set(X509CertInfo.SUBJECT, new CertificateSubjectName(owner));
    info.set(X509CertInfo.KEY, new CertificateX509Key(pubkey));
    info.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
    AlgorithmId algo = new AlgorithmId(AlgorithmId.sha256WithECDSA_oid);
    info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(algo));

    CertificateExtensions ext = new CertificateExtensions();
    ext.set(BasicConstraintsExtension.NAME, new BasicConstraintsExtension(Boolean.TRUE, ca, ca ? 0 : 1)); // Critical|isCA|pathLen
    KeyUsageExtension kue = new KeyUsageExtension();
    if (ca)
    {
      kue.set(KeyUsageExtension.KEY_CERTSIGN, true);
    }
    else
    {
      kue.set(KeyUsageExtension.NON_REPUDIATION, true);
    }
    ext.set(KeyUsageExtension.NAME, kue);

    info.set(X509CertInfo.EXTENSIONS, ext);

    // Sign the cert to identify the algorithm that's used.
    X509CertImpl cert = new X509CertImpl(info);
    cert.sign(privkey, "SHA256WithECDSA");

    // Update the algorith, and resign.
    algo = (AlgorithmId)cert.get(X509CertImpl.SIG_ALG);
    info.set(CertificateAlgorithmId.NAME + "." + CertificateAlgorithmId.ALGORITHM, algo);
    cert = new X509CertImpl(info);
    cert.sign(privkey, "SHA256WithECDSA");
    return cert;
  }

  /** {@inheritDoc} */
  @Override
  public boolean reportWrite(boolean arg0)
  {
    return true;
  }
}

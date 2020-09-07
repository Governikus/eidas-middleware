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
import java.math.BigInteger;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Set;


/**
 * DefectKnownParameter representing required parameters from known defects.
 *
 * @author Ole Behrens
 */
public class DefectKnownParameter
{

  private static final Log LOGGER = LogFactory.getLog(DefectKnownParameter.class.getName());

  private Object parameters;

  /**
   * StatusCode for defect type id-CertRevoked
   */
  public enum StatusCode
  {
    NO_INDICATION(0, "noIndication", "No details given"),
    ON_HOLD(1, "onHold", "Revocation under investigation"),
    TESTING(2, "testing", "The certificate has been used for testing purpose"),
    REVOKED_BY_ISSUER(3, "revokedByIssuer", "The Issuer has revoked the certificate by CRL"),
    REVOKED_DLS(4, "revokedDLS", "The Defect List Signer has revoked the certificate"),
    PROPRIETARY(32, "proprietary", "Status codes >=32 can be used for internal purposes");

    private int code;

    private String name;

    private String detail;

    private StatusCode(int code, String name, String detail)
    {
      this.code = code;
      this.name = name;
      this.detail = detail;
    }

    @Override
    public String toString()
    {
      return name + "(" + code + "),  -- " + detail;
    }
  }

  /**
   * Parameter object to identify parameters
   *
   * @param defectType with parameters
   * @param parameter data to parse
   * @throws IOException
   */
  DefectKnownParameter(DefectKnown.DefectType defectType, ASN1Encodable parameter) throws IOException
  {
    switch (defectType)
    {
      case ID_CERT_REVOKED:
        parameters = parseCertificateRevokedParameter(parameter);
        break;

      case ID_CERT_REPLACED:
        parameters = parseCertificateReplacedParameter(parameter);
        break;

      case ID_EPASSPORT_DG_MALFORMED:
        parameters = parseApplicationDGMalformedParameter(parameter);
        break;

      case ID_EID_DG_MALFORMED:
        parameters = parseApplicationDGMalformedParameter(parameter);
        break;

      case ID_CARD_SECURITY_MALFORMED:
        parameters = parseCardSecurityMalformedParameter(parameter);
        break;

      default:
        throw new IOException("Parameter handling for " + defectType.name() + " not implemented");
    }

    if (parameters == null)
    {
      throw new IOException("No parameters could be parsed for data: " + parameter);
    }
  }

  /**
   * Parse a Card Security Object while malformed
   *
   * @param parameter to be parsed
   * @return the object representing the parameter
   * @throws IOException
   */
  private static byte[] parseCardSecurityMalformedParameter(ASN1Encodable parameter) throws IOException
  {
    try
    {
      LOGGER.debug("Parsed CardSecurityMalformed parameter (new card secutiry object received)");
      return parameter.toASN1Primitive().getEncoded();
    }
    catch (IOException e)
    {
      throw new IOException("Unable to create a Card Security Object from data", e);
    }
  }

  /**
   * Parse certificate from data
   *
   * @param parameter to be parsed
   * @return the certificate to be replaced
   * @throws IOException
   * @throws NoSuchProviderException
   */
  private static X509Certificate parseCertificateReplacedParameter(ASN1Encodable parameter) throws IOException
  {
    try
    {
      byte[] certificateBytes = parameter.toASN1Primitive().getEncoded();
      try (ByteArrayInputStream stream = new ByteArrayInputStream(certificateBytes))
      {
        CertificateFactory factory = CertificateFactory.getInstance("X.509", "TODO CARD SECURITY PROVIDER");
        X509Certificate newCertificate = (X509Certificate)factory.generateCertificate(stream);
        LOGGER.debug("Parsed CertificateReplaced parameter (Found certificate to be placed)");
        return newCertificate;
      }
    }
    catch (CertificateException e)
    {
      throw new IOException("Can not get certificate from factory and data", e);
    }
    catch (NoSuchProviderException e)
    {
      throw new IOException(e);
    }
  }

  /**
   * Parse reason why certificate revoked. Reason is represented by a {@link StatusCode}
   *
   * @param parameter to be parsed
   * @return the code representing the revoke reason
   * @throws IOException
   */
  private static StatusCode parseCertificateRevokedParameter(ASN1Encodable parameter) throws IOException
  {
    if (parameter instanceof ASN1Enumerated)
    {
      ASN1Enumerated statusCodeEnum = (ASN1Enumerated)parameter;
      BigInteger value = statusCodeEnum.getValue();
      int code = value.intValue();
      for ( StatusCode statusCode : StatusCode.values() )
      {
        if (code == statusCode.code)
        {
          LOGGER.debug("Parsed CertificateRevoked parameter (revokation reason found)");
          return statusCode;
        }
      }
      throw new IOException("No status code found in parameters");
    }
    else
    {
      throw new IOException("Data has wrong format: " + parameter);
    }
  }

  /**
   * Data group on card malformed
   *
   * @param parameter set with defect data groups
   * @return the integers representing defect data groups
   * @throws IOException
   */
  private static int[] parseApplicationDGMalformedParameter(ASN1Encodable parameter) throws IOException
  {
    if (parameter instanceof ASN1Set)
    {
      ASN1Set set = (ASN1Set)parameter;
      int integers = set.size();
      int[] malformedDataGroups = new int[integers];
      for ( int dataGroups = 0 ; dataGroups < integers ; dataGroups++ )
      {
        ASN1Encodable objectAt = set.getObjectAt(dataGroups);
        if (objectAt instanceof ASN1Integer)
        {
          ASN1Integer integer = (ASN1Integer)objectAt;
          malformedDataGroups[dataGroups] = integer.getValue().intValue();
        }
        else
        {
          throw new IOException("Invalid data for data group");
        }
      }

      LOGGER.debug("Parsed ApplicationDGMalformed parameter (defect data groups received)");
      return malformedDataGroups;
    }
    else
    {
      throw new IOException("Data is no set to be able to extract data group integers");
    }
  }

  /**
   * Get the parameter object from this instance
   *
   * @return inner parameter for this instance
   */
  public Object getParameterObject()
  {
    return parameters;
  }
}

/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.configuration.wizard.web.model;

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.security.auth.x500.X500Principal;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;

import org.springframework.web.multipart.MultipartFile;

import de.governikus.eumw.configuration.wizard.web.handler.NamedObject;
import de.governikus.eumw.utils.key.KeyReader;
import de.governikus.eumw.utils.key.exceptions.CertificateCreationException;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;


/**
 * project: eumw <br>
 * author Pascal Knueppel <br>
 * created at: 12.02.2018 - 08:16 <br>
 * <br>
 * this form will be used with thymeleaf to upload certificate files
 */
@Slf4j
@Data
@NoArgsConstructor
@ToString(exclude = {"certificate"})
public class CertificateForm implements NamedObject
{

  /**
   * the number of milliseconds that are equal to 24 hours
   */
  private static final double DAY_IN_MILLIS = 86400000.0d;

  /**
   * the keystore file that was uploaded
   */
  @NotNull(message = "File must not be empty.")
  private MultipartFile certificateFile;

  /**
   * the name of this certificate file that will be displayed in selections in the view
   */
  @NotBlank(message = "Name must not be empty.")
  private String certificateName;

  /**
   * this is the java representation of the {@link #certificateFile}
   */
  private transient X509Certificate certificate;

  /**
   * lombok builder constructor
   */
  @Builder
  public CertificateForm(MultipartFile certificateFile, String certificateName, X509Certificate certificate)
  {
    this.certificateFile = certificateFile;
    this.certificateName = certificateName;
    this.certificate = certificate;
  }

  /**
   * @see #certificate
   */
  public X509Certificate getCertificate()
  {
    if (certificate == null && certificateFile != null)
    {
      byte[] certBytes;
      try
      {
        certBytes = certificateFile.getBytes();
      }
      catch (IOException e)
      {
        throw new CertificateCreationException("could not load certificate from file '"
          + certificateFile.getOriginalFilename() + "'", e);
      }
      if (certBytes == null || certBytes.length == 0)
      {
        throw new CertificateCreationException("could not read certificate for empty certificate bytes");
      }
      certificate = KeyReader.readX509Certificate(certBytes);
    }
    else if (certificate == null)
    {
      throw new CertificateCreationException("could not load certificate... \ncertificate-name = "
                                             + certificateName + "\ncertificate = " + certificate
                                             + "\ncertificateFile = " + certificateFile);
    }
    return certificate;
  }

  /**
   * @see X509Certificate#getSerialNumber()
   */
  public BigInteger getSerialnumber()
  {
    return getCertificate().getSerialNumber();
  }

  /**
   * @see X509Certificate#getIssuerX500Principal()
   */
  public String getIssuer()
  {
    X500Principal issuer = getCertificate().getIssuerX500Principal();
    return issuer == null ? null : issuer.toString();
  }

  /**
   * @see X509Certificate#getSubjectX500Principal()
   */
  public String getSubject()
  {
    X500Principal subject = getCertificate().getSubjectX500Principal();
    return subject == null ? null : subject.toString();
  }

  /**
   * @see X509Certificate#getNotBefore()
   */
  public Date getNotBefore()
  {
    return getCertificate().getNotBefore();
  }

  /**
   * @see X509Certificate#getNotAfter()
   */
  public Date getNotAfter()
  {
    return getCertificate().getNotAfter();
  }

  /**
   * @return If the result is positive, it denotes the remaining number of days of the certificate's validity
   *         period. A negative result counts the number of days the certificate already has exceeded the
   *         expiration date.
   */
  public double getRemainingOrExceedingValidityDays()
  {
    if (getCertificate() == null)
    {
      return 0.0d;
    }

    return (int) ((getCertificate().getNotAfter().getTime() - System.currentTimeMillis()) / DAY_IN_MILLIS);
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public String getName()
  {
    return certificateName;
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public boolean isValid()
  {
    try
    {
      getCertificate();
    }
    catch (CertificateCreationException ex)
    {
      log.warn("could not read certificate '{}' for '{}'", certificateName, ex.getMessage());
      return false;
    }
    return true;
  }
}

package de.governikus.eumw.utils.key.exceptions;

/**
 * This exception will be thrown when an unsupported EC certificate is configured for tls.
 */
public class UnsupportedECCertificateException extends Exception
{

  public UnsupportedECCertificateException(String message)
  {
    super(message);
  }
}

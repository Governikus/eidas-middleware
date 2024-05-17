package de.governikus.eumw.poseidas.server.pki;

/**
 * Thrown when a CSR for a new TLS client cert cannot be created
 */
public class InvalidCsrException extends Exception
{

  public InvalidCsrException(String s)
  {
    super(s);
  }
}

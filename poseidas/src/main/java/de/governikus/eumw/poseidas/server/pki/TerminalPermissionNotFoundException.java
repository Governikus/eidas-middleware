package de.governikus.eumw.poseidas.server.pki;

public class TerminalPermissionNotFoundException extends Exception
{

  private static final long serialVersionUID = -5443767864220707605L;

  public TerminalPermissionNotFoundException()
  {}

  public TerminalPermissionNotFoundException(String message)
  {
    super(message);
  }
}

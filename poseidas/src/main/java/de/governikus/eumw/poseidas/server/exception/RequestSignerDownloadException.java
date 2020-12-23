package de.governikus.eumw.poseidas.server.exception;

import lombok.Getter;


public class RequestSignerDownloadException extends Exception
{

  static final long serialVersionUID = 797190742766939L;

  @Getter
  private final String entityId;

  public RequestSignerDownloadException(String entityId)
  {
    this.entityId = entityId;
  }
}

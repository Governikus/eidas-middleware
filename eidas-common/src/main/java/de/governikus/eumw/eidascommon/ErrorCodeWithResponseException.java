package de.governikus.eumw.eidascommon;

import lombok.Getter;


@Getter
public class ErrorCodeWithResponseException extends ErrorCodeException
{


  private String issuer;

  private String requestId;

  public ErrorCodeWithResponseException(ErrorCode code, String issuer, String requestId, String... detail)
  {
    super(code, detail);
    this.issuer = issuer;
    this.requestId = requestId;
  }

  public ErrorCodeWithResponseException(ErrorCode code, Throwable t)
  {
    super(code, t);
  }
}

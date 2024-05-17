package de.governikus.eumw.poseidas.server.pki.caserviceaccess.logging;

import lombok.AllArgsConstructor;


/**
 * Simple POJO that contains the data of a SOAP message to be logged and a toString method with readable output.
 */
@AllArgsConstructor
class LogInformation
{

  private final String address;

  private final String type;

  private final Class<?> clientClass;

  private final String operationName;

  private final String payload;

  @Override
  public String toString()
  {
    return "Logging SOAP Message:\n" + "{" + "type='" + type + "',\n" + "address='" + address + "',\n" + "clientClass='"
           + clientClass.getSimpleName() + "',\n" + "operationName='" + operationName + "',\n" + "payload='" + payload
           + "'\n" + '}';
  }
}

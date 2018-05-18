/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.paosservlet.authentication;

/**
 * PAOSConstants needed for communication between eID-Server and several kinds of client
 * 
 * @author <a href="mail:obe@bos-bremen.de">Ole Behrens</a>
 */
public final class AuthenticationConstants
{

  public static final String PAOS_1_1_URN = "urn:liberty:paos:2003-08";

  public static final String PAOS_2_0_URN = "urn:liberty:paos:2006-08";

  /**
   * ECA-429: Also accept the wrong header of the BC
   */
  public static final String PAOS_1_1_URN_BC_QUIRKSMODE = "urn:liberty:2003-08";

  /**
   * ECA-429: Also accept the wrong header of the BC
   */
  public static final String PAOS_2_0_URN_BC_QUIRKSMODE = "urn:liberty:2006-08";

  /**
   * Name of the PAOS version HTML header.
   */
  public static final String PAOS_VERSION_HEADER_NAME = "PAOS";

  /**
   * Value of the Accept HTML header when sending a PAOS request.
   */
  public static final String PAOS_MEDIA_TYPE = "application/vnd.paos+xml";

  /**
   * name of the HTML Accept header
   */
  public static final String ACCEPT_HEADER_NAME = "accept";

  private AuthenticationConstants()
  {}

}

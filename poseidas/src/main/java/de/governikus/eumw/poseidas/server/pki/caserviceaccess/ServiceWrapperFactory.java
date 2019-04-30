/*
 * Copyright (c) 2019 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.pki.caserviceaccess;

import java.net.URISyntaxException;


/**
 * Factory to the the service wrappers. Using this factory enables the client code to cope with different
 * service classes for the same service (different WSDL and schema versions).
 *
 * @author tautenhahn
 */
public class ServiceWrapperFactory
{

  public static final String WSDL_VERSION_1_0 = "1.0";

  public static final String WSDL_VERSION_1_1 = "1.1";

  private static final String WRONG_WSDL_VERSION_PREFIX = "unsupported wsdl version ";

  /**
   * Return a wrapper for the service to get master and defect lists from.
   *
   * @param con
   * @param uri
   * @param wsdlVersion
   * @throws URISyntaxException
   */
  public static PassiveAuthServiceWrapper createPassiveAuthServiceWrapper(PKIServiceConnector con,
                                                                          String uri,
                                                                          String wsdlVersion)
    throws URISyntaxException
  {
    if (WSDL_VERSION_1_0.equals(wsdlVersion))
    {
      return new PassiveAuthServiceWrapper10(con, uri);
    }
    else if (WSDL_VERSION_1_1.equals(wsdlVersion))
    {
      return new PassiveAuthServiceWrapper11(con, uri);
    }
    throw new IllegalArgumentException(WRONG_WSDL_VERSION_PREFIX + wsdlVersion);
  }

  /**
   * return wrapper for the service which gives us sector public keys and blacklists
   *
   * @param con
   * @param uri
   * @param wsdlVersion
   * @throws URISyntaxException
   */
  public static RestrictedIdServiceWrapper createRestrictedIdServiceWrapper(PKIServiceConnector con,
                                                                            String uri,
                                                                            String wsdlVersion)
    throws URISyntaxException
  {
    if (WSDL_VERSION_1_0.equals(wsdlVersion))
    {
      return new RestrictedIdServiceWrapper10(con, uri);
    }
    else if (WSDL_VERSION_1_1.equals(wsdlVersion))
    {
      return new RestrictedIdServiceWrapper11(con, uri);
    }
    throw new IllegalArgumentException(WRONG_WSDL_VERSION_PREFIX + wsdlVersion);
  }

  /**
   * return wrapper for the service which gives us CVCs and CA certificates
   *
   * @param con
   * @param uri
   * @param wsdlVersion
   * @throws URISyntaxException
   */
  public static TermAuthServiceWrapper createTermAuthServiceWrapper(PKIServiceConnector con,
                                                                    String uri,
                                                                    String wsdlVersion)
    throws URISyntaxException
  {
    if (WSDL_VERSION_1_0.equals(wsdlVersion))
    {
      return new TermAuthServiceWrapper10(con, uri);
    }
    else if (WSDL_VERSION_1_1.equals(wsdlVersion))
    {
      return new TermAuthServiceWrapper11(con, uri);
    }
    throw new IllegalArgumentException(WRONG_WSDL_VERSION_PREFIX + wsdlVersion);
  }

  /**
   * return wrapper for the service which gives us CVCs and CA certificates
   *
   * @param con
   * @param uri
   * @param wsdlVersion
   * @throws URISyntaxException
   */
  public static DvcaCertDescriptionWrapper createDvcaCertDescriptionWrapper(PKIServiceConnector con,
                                                                            String uri,
                                                                            String wsdlVersion)
    throws URISyntaxException
  {
    return new DvcaCertDescriptionWrapper10(con, uri);
  }

}

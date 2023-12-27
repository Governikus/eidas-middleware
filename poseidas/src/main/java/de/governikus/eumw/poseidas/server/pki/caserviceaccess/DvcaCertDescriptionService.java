/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.pki.caserviceaccess;

import java.net.URISyntaxException;

import jakarta.xml.ws.BindingProvider;

import dvca.v2.DVCACERTDESCRIPTION;
import dvca.v2.DVCACertDescriptionService;
import dvca.v2.types.GetCertificateDescriptionRequest;
import dvca.v2.types.GetCertificateDescriptionResponse;


/**
 * Interface to service to fetch a certificate Description form a Ber CA. Only the D-Trust CA supports this interface.
 *
 * @author mehrtens
 */
public class DvcaCertDescriptionService
{

  private final DVCACERTDESCRIPTION port;

  /**
   * @param con
   * @param uri
   * @throws URISyntaxException
   */
  public DvcaCertDescriptionService(PKIServiceConnector con, String uri) throws URISyntaxException
  {
    DVCACertDescriptionService service = new DVCACertDescriptionService(getClass().getResource("/META-INF/wsdl/CA-Services/CertDesc/WS_DV_CertDesc.wsdl"));
    DVCACERTDESCRIPTION tmpPort = service.getSoap12();
    con.setHttpsConnectionSetting((BindingProvider)tmpPort, uri);
    port = tmpPort;
  }

  /**
   * Returns a certificate Description for a given hash.
   *
   * @param hash
   */
  public byte[] getCertificateDescription(byte[] hash)
  {
    GetCertificateDescriptionRequest request = new GetCertificateDescriptionRequest();
    request.setHash(hash);
    GetCertificateDescriptionResponse result = port.getCertificateDescription(request);
    return result.getCertificateDescription();
  }

}

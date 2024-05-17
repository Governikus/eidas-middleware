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

import de.governikus.eumw.poseidas.services.passive.auth.wsdl.v1_4_0.CallbackIndicatorType;
import de.governikus.eumw.poseidas.services.passive.auth.wsdl.v1_4_0.GetDefectListRequest;
import de.governikus.eumw.poseidas.services.passive.auth.wsdl.v1_4_0.GetDefectListResult;
import de.governikus.eumw.poseidas.services.passive.auth.wsdl.v1_4_0.GetMasterListRequest;
import de.governikus.eumw.poseidas.services.passive.auth.wsdl.v1_4_0.GetMasterListResult;
import de.governikus.eumw.poseidas.services.passive.auth.wsdl.v1_4_0.GetReturnCodeType;
import de.governikus.eumw.poseidas.services.passive.auth.wsdl.v1_4_0.PassiveAuthWebService_1_4_0;
import de.governikus.eumw.poseidas.services.passive.auth.wsdl.v1_4_0.PassiveAuthWebserviceClient_1_4_0;
import lombok.extern.slf4j.Slf4j;


/**
 * Class to abstract from the actual service class, mainly to keep the imports in. Remember that all the CA services
 * have the same name.
 *
 * @author tautenhahn
 */
@Slf4j
public class PassiveAuthService
{

  private final PassiveAuthWebService_1_4_0 port;


  PassiveAuthService(PKIServiceConnector con, String uri) throws URISyntaxException
  {
    PassiveAuthWebserviceClient_1_4_0 service = new PassiveAuthWebserviceClient_1_4_0(getClass().getResource("META-INF/wsdl/CA-Services-1-4-0/part-3/passiveAuth/WS_DV_PassiveAuth.wsdl"));
    PassiveAuthWebService_1_4_0 tmpPort = service.getEACDVProtocolServicePort();
    con.setHttpsConnectionSetting((BindingProvider)tmpPort, uri);
    con.setMessageLogger((BindingProvider)tmpPort);
    port = tmpPort;
  }


  public byte[] getMasterList()
  {
    GetMasterListRequest masterListRequest = new GetMasterListRequest();
    masterListRequest.setCallbackIndicator(CallbackIndicatorType.CALLBACK_NOT_POSSIBLE);

    GetMasterListResult mResult = port.getMasterList(masterListRequest);
    if (GetReturnCodeType.OK_LIST_AVAILABLE != mResult.getReturnCode())
    {
      log.error("Could not receive master list. The return code from the server was: {}", mResult.getReturnCode());
      return null;
    }
    return mResult.getMasterList().getBinary();
  }


  public byte[] getDefectList()
  {
    GetDefectListRequest defectListRequest = new GetDefectListRequest();

    defectListRequest.setCallbackIndicator(CallbackIndicatorType.CALLBACK_NOT_POSSIBLE);

    GetDefectListResult mResult = port.getDefectList(defectListRequest);
    if (GetReturnCodeType.OK_LIST_AVAILABLE != mResult.getReturnCode())
    {
      log.error("Could not receive defect list. The return code from the server was: {}", mResult.getReturnCode());
      return null;
    }
    return mResult.getDefectList().getBinary();
  }
}

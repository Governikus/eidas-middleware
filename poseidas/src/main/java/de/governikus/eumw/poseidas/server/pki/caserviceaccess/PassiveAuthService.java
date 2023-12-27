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

import lombok.extern.slf4j.Slf4j;
import uri.eac_pki_is_protocol._1.passiveAuth.dv.EACDVProtocolService;
import uri.eac_pki_is_protocol._1.passiveAuth.dv.EACPKIDVProtocolType;
import uri.eacbt._1.passiveAuth.dv.CallbackIndicatorType;
import uri.eacbt._1.passiveAuth.dv.GetDefectListResult;
import uri.eacbt._1.passiveAuth.dv.GetDefectListReturnCodeType;
import uri.eacbt._1.passiveAuth.dv.GetMasterListResult;
import uri.eacbt._1.passiveAuth.dv.GetMasterListReturnCodeType;
import uri.eacbt._1.passiveAuth.dv.OptionalMessageIDType;
import uri.eacbt._1.passiveAuth.dv.OptionalStringType;


/**
 * Class to abstract from the actual service class, mainly to keep the imports in. Remember that all the CA services
 * have the same name.
 *
 * @author tautenhahn
 */
@Slf4j
public class PassiveAuthService
{

  private static final OptionalMessageIDType EMPTY_MESSAGE_ID = new OptionalMessageIDType();
  private static final OptionalStringType EMPTY_RESPONSE_URL = new OptionalStringType();
  private final EACPKIDVProtocolType port;


  public PassiveAuthService(PKIServiceConnector con, String uri) throws URISyntaxException
  {
    EACDVProtocolService service = new EACDVProtocolService(getClass().getResource("/META-INF/wsdl/CA-Services/PassiveAuth/WS_DV_PassiveAuth.wsdl"));
    EACPKIDVProtocolType tmpPort = service.getEACDVProtocolServicePort();
    con.setHttpsConnectionSetting((BindingProvider)tmpPort, uri);
    port = tmpPort;
  }


  public byte[] getMasterList()
  {
    GetMasterListResult mResult = port.getMasterList(CallbackIndicatorType.CALLBACK_NOT_POSSIBLE,
                                                     EMPTY_MESSAGE_ID,
                                                     EMPTY_RESPONSE_URL);
    if (GetMasterListReturnCodeType.OK_LIST_AVAILABLE != mResult.getReturnCode())
    {
      log.error("Could not receive master list. The return code from the server was: {}", mResult.getReturnCode());
      return null;
    }
    return mResult.getMasterList().getBinary();
  }


  public byte[] getDefectList()
  {
    GetDefectListResult mResult = port.getDefectList(CallbackIndicatorType.CALLBACK_NOT_POSSIBLE,
                                                     EMPTY_MESSAGE_ID,
                                                     EMPTY_RESPONSE_URL);
    if (GetDefectListReturnCodeType.OK_LIST_AVAILABLE != mResult.getReturnCode())
    {
      log.error("Could not receive defect list. The return code from the server was: {}", mResult.getReturnCode());
      return null;
    }
    return mResult.getDefectList().getBinary();
  }

}

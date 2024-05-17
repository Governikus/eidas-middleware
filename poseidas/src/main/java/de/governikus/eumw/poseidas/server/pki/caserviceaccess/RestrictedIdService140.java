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

import org.apache.hc.client5.http.utils.Base64;

import de.governikus.eumw.poseidas.gov2server.GovManagementException;
import de.governikus.eumw.poseidas.gov2server.constants.admin.GlobalManagementCodes;
import de.governikus.eumw.poseidas.services.restricted.id.wsdl.v1_4_0.ConditionalDeltaBaseType;
import de.governikus.eumw.poseidas.services.restricted.id.wsdl.v1_4_0.DeltaIndicatorType;
import de.governikus.eumw.poseidas.services.restricted.id.wsdl.v1_4_0.GetBlockListRequest;
import de.governikus.eumw.poseidas.services.restricted.id.wsdl.v1_4_0.GetBlockListResult;
import de.governikus.eumw.poseidas.services.restricted.id.wsdl.v1_4_0.GetBlockListReturnCodeType;
import de.governikus.eumw.poseidas.services.restricted.id.wsdl.v1_4_0.GetSectorPublicKeyRequest;
import de.governikus.eumw.poseidas.services.restricted.id.wsdl.v1_4_0.GetSectorPublicKeyResult;
import de.governikus.eumw.poseidas.services.restricted.id.wsdl.v1_4_0.GetSectorPublicKeyReturnCodeType;
import de.governikus.eumw.poseidas.services.restricted.id.wsdl.v1_4_0.OptionalStringType;
import de.governikus.eumw.poseidas.services.restricted.id.wsdl.v1_4_0.RestrictedIdWebService_1_4_0;
import de.governikus.eumw.poseidas.services.restricted.id.wsdl.v1_4_0.RestrictedIdWebserviceClient_1_4_0;


/**
 * Wrapper around {@link RestrictedIdWebserviceClient_1_4_0}
 */
public class RestrictedIdService140 implements RestrictedIdService
{

  public static final BlackListResult NO_NEW_DATA = new BlackListResult("no new data");

  private RestrictedIdWebService_1_4_0 port;

  /**
   * @param con
   * @param uri
   * @throws URISyntaxException
   */
  RestrictedIdService140(PKIServiceConnector con, String uri) throws URISyntaxException
  {
    RestrictedIdWebserviceClient_1_4_0 service = new RestrictedIdWebserviceClient_1_4_0(getClass().getResource("META-INF/wsdl/CA-Services-1-4-0/part-3/restrictedID/WS_DV_RestrictedIdentification.wsdl"));
    RestrictedIdWebService_1_4_0 tmpPort = service.getEACDVProtocolServicePort();
    con.setHttpsConnectionSetting((BindingProvider)tmpPort, uri);
    con.setMessageLogger((BindingProvider)tmpPort);
    port = tmpPort;
  }

  @Override
  public BlackListResult getBlacklistResult(byte[] deltabase, byte[] sectorID) throws GovManagementException
  {
    GetBlockListRequest blockListRequest = new GetBlockListRequest();
    DeltaIndicatorType deltaIndicator = deltabase == null ? DeltaIndicatorType.COMPLETE_LIST
      : DeltaIndicatorType.DELTA_LIST;
    blockListRequest.setCallbackIndicator(de.governikus.eumw.poseidas.services.restricted.id.wsdl.v1_4_0.CallbackIndicatorType.CALLBACK_NOT_POSSIBLE);
    blockListRequest.setDeltaIndicator(deltaIndicator);

    // Add sector id to block list request
    if (sectorID != null)
    {
      OptionalStringType sectorIdType = new OptionalStringType();
      // TR-3129-3 v1.40 does not specify in chapter 5.3.1, how the sectorID must be encoded in this request.
      sectorIdType.setString(Base64.encodeBase64String(sectorID));
      blockListRequest.setSectorID(sectorIdType);
    }

    if (deltabase != null)
    {
      ConditionalDeltaBaseType conditionalDeltaBaseType = new ConditionalDeltaBaseType();
      conditionalDeltaBaseType.setDeltaBase(deltabase);
      blockListRequest.setDeltaBase(conditionalDeltaBaseType);
    }
    GetBlockListResult result = port.getBlockList(blockListRequest);
    if (GetBlockListReturnCodeType.OK_NO_UPDATE_NEEDED == result.getReturnCode())
    {
      return NO_NEW_DATA;
    }
    if (deltabase == null && GetBlockListReturnCodeType.OK_LIST_AVAILABLE == result.getReturnCode()
        || GetBlockListReturnCodeType.OK_COMPLETE_LIST == result.getReturnCode())
    {
      return new BlackListResult(result.getCompleteListURL().getString());
    }
    if (deltabase != null && GetBlockListReturnCodeType.OK_LIST_AVAILABLE == result.getReturnCode())
    {
      return new BlackListResult(result.getDeltaListAddedItems().getBinary(),
                                 result.getDeltaListRemovedItems().getBinary());
    }
    throw new GovManagementException(GlobalManagementCodes.EC_UNEXPECTED_ERROR,
                                     "getBlackList for returned " + result.getReturnCode());
  }


  @Override
  public byte[] getSectorPublicKey(byte[] sectorId) throws GovManagementException
  {
    GetSectorPublicKeyRequest sectorPublicKeyRequest = new GetSectorPublicKeyRequest();
    sectorPublicKeyRequest.setSectorID(sectorId);
    GetSectorPublicKeyResult result = port.getSectorPublicKey(sectorPublicKeyRequest);
    if (GetSectorPublicKeyReturnCodeType.OK_PK_AVAILABLE != result.getReturnCode())
    {
      throw new GovManagementException(GlobalManagementCodes.EC_UNEXPECTED_ERROR,
                                       "getSectorPublicKey returned " + result.getReturnCode());
    }

    return result.getSectorPK().getSectorPK();
  }

  // For Testing
  void setPort(RestrictedIdWebService_1_4_0 port)
  {
    this.port = port;
  }
}


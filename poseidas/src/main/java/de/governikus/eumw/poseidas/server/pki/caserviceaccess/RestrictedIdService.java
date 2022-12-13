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

import javax.xml.ws.BindingProvider;

import de.governikus.eumw.poseidas.gov2server.GovManagementException;
import de.governikus.eumw.poseidas.gov2server.constants.admin.GlobalManagementCodes;
import lombok.Getter;
import uri.eac_pki_is_protocol._1.restrictedId.dv.EACDVProtocolService;
import uri.eac_pki_is_protocol._1.restrictedId.dv.EACPKIDVProtocolType;
import uri.eacbt._1.restrictedId.dv.CallbackIndicatorType;
import uri.eacbt._1.restrictedId.dv.DeltaIndicatorType;
import uri.eacbt._1.restrictedId.dv.GetBlackListResult;
import uri.eacbt._1.restrictedId.dv.GetBlackListReturnCodeType;
import uri.eacbt._1.restrictedId.dv.GetSectorPublicKeyResult;
import uri.eacbt._1.restrictedId.dv.GetSectorPublicKeyReturnCodeType;
import uri.eacbt._1.restrictedId.dv.OptionalDeltaBaseType;
import uri.eacbt._1.restrictedId.dv.OptionalMessageIDType;
import uri.eacbt._1.restrictedId.dv.OptionalStringType;


/**
 * Wrapper around uri.eac_pki_is_protocol._1_1.restrictedId.dv.EACDVProtocolService-
 *
 * @author tautenhahn, hme
 */
public class RestrictedIdService
{

  public static final BlackListResult NO_NEW_DATA = new BlackListResult("no new data");

  private final EACPKIDVProtocolType port;

  /**
   * @param con
   * @param uri
   * @throws URISyntaxException
   */
  public RestrictedIdService(PKIServiceConnector con, String uri) throws URISyntaxException
  {
    EACDVProtocolService service = new EACDVProtocolService(getClass().getResource("/META-INF/wsdl/CA-Services/Restricted_ID/WS_DV_RestrictedID.wsdl"));
    EACPKIDVProtocolType tmpPort = service.getEACDVProtocolServicePort();
    con.setHttpsConnectionSetting((BindingProvider)tmpPort, uri);
    port = tmpPort;
  }

  public BlackListResult getBlacklistResult(byte[] deltabase) throws GovManagementException
  {
    DeltaIndicatorType deltaIndicator = deltabase == null ? DeltaIndicatorType.COMPLETE_LIST
      : DeltaIndicatorType.DELTA_LIST;
    OptionalDeltaBaseType base = new OptionalDeltaBaseType();
    if (deltabase != null)
    {
      base.setDeltaBase(deltabase);
    }
    GetBlackListResult result = port.getBlackList(CallbackIndicatorType.CALLBACK_NOT_POSSIBLE,
                                                  new OptionalMessageIDType(),
                                                  new OptionalStringType(),
                                                  deltaIndicator,
                                                  base);
    if (GetBlackListReturnCodeType.OK_NO_UPDATE_NEEDED == result.getReturnCode())
    {
      return NO_NEW_DATA;
    }
    if ((deltabase == null && GetBlackListReturnCodeType.OK_LIST_AVAILABLE == result.getReturnCode())
        || GetBlackListReturnCodeType.OK_COMPLETE_LIST == result.getReturnCode())
    {
      return new BlackListResult(result.getCompleteListURL().getString());
    }
    if (deltabase != null && GetBlackListReturnCodeType.OK_LIST_AVAILABLE == result.getReturnCode())
    {
      return new BlackListResult(result.getDeltaListAddedItems().getBinary(),
                                 result.getDeltaListRemovedItems().getBinary());
    }
    throw new GovManagementException(GlobalManagementCodes.EC_UNEXPECTED_ERROR,
                                     "getBlackList for returned " + result.getReturnCode());
  }


  public byte[] getSectorPublicKey(byte[] sectorId) throws GovManagementException
  {
    GetSectorPublicKeyResult result = port.getSectorPublicKey(sectorId);
    if (GetSectorPublicKeyReturnCodeType.OK_PK_AVAILABLE != result.getReturnCode())
    {
      throw new GovManagementException(GlobalManagementCodes.EC_UNEXPECTED_ERROR,
                                       "getSectorPublicKey returned " + result.getReturnCode());
    }

    return result.getSectorPK();
  }

  /**
   * Data object to hold the result of a blacklist request, either two delta lists or an URI to download the complete
   * list.
   */
  @Getter
  public static class BlackListResult
  {

    private String uri;

    private byte[] deltaAdded;

    private byte[] deltaRemoved;

    BlackListResult(String uri)
    {
      super();
      this.uri = uri;
    }

    BlackListResult(byte[] added, byte[] removed)
    {
      super();
      this.deltaAdded = added;
      this.deltaRemoved = removed;
    }

  }

}


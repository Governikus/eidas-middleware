package de.governikus.eumw.poseidas.server.pki.caserviceaccess;

import java.net.URISyntaxException;

import jakarta.xml.ws.BindingProvider;

import de.governikus.eumw.poseidas.gov2server.GovManagementException;
import de.governikus.eumw.poseidas.gov2server.constants.admin.GlobalManagementCodes;
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


public class RestrictedIdService110 implements RestrictedIdService
{


  public static final BlackListResult NO_NEW_DATA = new BlackListResult("no new data");

  private EACPKIDVProtocolType port;

  /**
   * @param con
   * @param uri
   * @throws URISyntaxException
   */
  RestrictedIdService110(PKIServiceConnector con, String uri) throws URISyntaxException
  {
    EACDVProtocolService service = new EACDVProtocolService(getClass().getResource("/META-INF/wsdl/CA-Services/Restricted_ID/WS_DV_RestrictedID.wsdl"));
    EACPKIDVProtocolType tmpPort = service.getEACDVProtocolServicePort();
    con.setHttpsConnectionSetting((BindingProvider)tmpPort, uri);
    con.setMessageLogger((BindingProvider)tmpPort);
    port = tmpPort;
  }

  @Override
  public BlackListResult getBlacklistResult(byte[] deltabase, byte[] sectorID) throws GovManagementException
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
    if (deltabase == null && GetBlackListReturnCodeType.OK_LIST_AVAILABLE == result.getReturnCode()
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

  @Override
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


  // For Testing
  void setPort(EACPKIDVProtocolType port)
  {
    this.port = port;
  }
}

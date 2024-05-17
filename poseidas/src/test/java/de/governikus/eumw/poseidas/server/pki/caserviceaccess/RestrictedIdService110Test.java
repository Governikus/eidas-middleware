package de.governikus.eumw.poseidas.server.pki.caserviceaccess;

import java.nio.charset.StandardCharsets;

import org.apache.commons.lang3.ArrayUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import de.governikus.eumw.poseidas.gov2server.GovManagementException;
import de.governikus.eumw.poseidas.gov2server.constants.admin.GlobalManagementCodes;
import uri.eac_pki_is_protocol._1.restrictedId.dv.EACPKIDVProtocolType;
import uri.eacbt._1.restrictedId.dv.CallbackIndicatorType;
import uri.eacbt._1.restrictedId.dv.DeltaIndicatorType;
import uri.eacbt._1.restrictedId.dv.GetBlackListResult;
import uri.eacbt._1.restrictedId.dv.GetBlackListReturnCodeType;
import uri.eacbt._1.restrictedId.dv.GetSectorPublicKeyResult;
import uri.eacbt._1.restrictedId.dv.GetSectorPublicKeyReturnCodeType;
import uri.eacbt._1.restrictedId.dv.OptionalBinaryType;
import uri.eacbt._1.restrictedId.dv.OptionalDeltaBaseType;
import uri.eacbt._1.restrictedId.dv.OptionalMessageIDType;
import uri.eacbt._1.restrictedId.dv.OptionalStringType;


@ExtendWith(MockitoExtension.class)
class RestrictedIdService110Test
{

  @Mock
  PKIServiceConnector connector;

  @Mock
  EACPKIDVProtocolType port;

  private RestrictedIdService110 restrictedIdService110;

  @BeforeEach
  void setUp() throws Exception
  {
    restrictedIdService110 = new RestrictedIdService110(connector, "https://riURL");
    restrictedIdService110.setPort(port);
  }

  @Test
  void testBlResult() throws Exception
  {

    GetBlackListResult blackListResult = new GetBlackListResult();
    // No Update Needed
    blackListResult.setReturnCode(GetBlackListReturnCodeType.OK_NO_UPDATE_NEEDED);
    Mockito.when(port.getBlackList(Mockito.eq(CallbackIndicatorType.CALLBACK_NOT_POSSIBLE),
                                   Mockito.any(OptionalMessageIDType.class),
                                   Mockito.any(OptionalStringType.class),
                                   Mockito.eq(DeltaIndicatorType.DELTA_LIST),
                                   Mockito.any(OptionalDeltaBaseType.class)))
           .thenReturn(blackListResult);
    RestrictedIdService.BlackListResult result = restrictedIdService110.getBlacklistResult(ArrayUtils.EMPTY_BYTE_ARRAY, null);
    Assertions.assertEquals(RestrictedIdService110.NO_NEW_DATA, result);

    // Delta List
    blackListResult.setReturnCode(GetBlackListReturnCodeType.OK_LIST_AVAILABLE);
    OptionalBinaryType optionalBinaryType = new OptionalBinaryType();
    optionalBinaryType.setBinary(ArrayUtils.EMPTY_BYTE_ARRAY);
    blackListResult.setDeltaListAddedItems(optionalBinaryType);
    blackListResult.setDeltaListRemovedItems(optionalBinaryType);
    Mockito.when(port.getBlackList(Mockito.eq(CallbackIndicatorType.CALLBACK_NOT_POSSIBLE),
                                   Mockito.any(OptionalMessageIDType.class),
                                   Mockito.any(OptionalStringType.class),
                                   Mockito.eq(DeltaIndicatorType.DELTA_LIST),
                                   Mockito.any(OptionalDeltaBaseType.class)))
           .thenReturn(blackListResult);
    result = restrictedIdService110.getBlacklistResult(ArrayUtils.EMPTY_BYTE_ARRAY, null);
    Assertions.assertArrayEquals(result.getDeltaAdded(), optionalBinaryType.getBinary());
    Assertions.assertArrayEquals(result.getDeltaRemoved(), optionalBinaryType.getBinary());

    // Complete List
    blackListResult.setReturnCode(GetBlackListReturnCodeType.OK_LIST_AVAILABLE);
    OptionalStringType optionalStringType = new OptionalStringType();
    optionalStringType.setString("http//downloadBL");
    blackListResult.setCompleteListURL(optionalStringType);
    Mockito.when(port.getBlackList(Mockito.eq(CallbackIndicatorType.CALLBACK_NOT_POSSIBLE),
                                   Mockito.any(OptionalMessageIDType.class),
                                   Mockito.any(OptionalStringType.class),
                                   Mockito.eq(DeltaIndicatorType.COMPLETE_LIST),
                                   Mockito.any(OptionalDeltaBaseType.class)))
           .thenReturn(blackListResult);
    result = restrictedIdService110.getBlacklistResult(null, null);
    Assertions.assertEquals("http//downloadBL", result.getUri());

    // GovManagementException
    blackListResult.setReturnCode(GetBlackListReturnCodeType.FAILURE_INTERNAL_ERROR);
    Mockito.when(port.getBlackList(Mockito.eq(CallbackIndicatorType.CALLBACK_NOT_POSSIBLE),
                                   Mockito.any(OptionalMessageIDType.class),
                                   Mockito.any(OptionalStringType.class),
                                   Mockito.eq(DeltaIndicatorType.COMPLETE_LIST),
                                   Mockito.any(OptionalDeltaBaseType.class)))
           .thenReturn(blackListResult);
    GovManagementException govManagementException = Assertions.assertThrows(GovManagementException.class,
                                                                            () -> restrictedIdService110.getBlacklistResult(null, null));
    Assertions.assertEquals(GlobalManagementCodes.EC_UNEXPECTED_ERROR,
                            govManagementException.getManagementMessage().getCode());
    Assertions.assertEquals("getBlackList for returned " + GetBlackListReturnCodeType.FAILURE_INTERNAL_ERROR,
                            govManagementException.getManagementMessage().getDetails());
  }

  @Test
  void testGetSectorPublicKey() throws Exception
  {
    GetSectorPublicKeyResult sectorPublicKeyResult = new GetSectorPublicKeyResult();
    sectorPublicKeyResult.setReturnCode(GetSectorPublicKeyReturnCodeType.OK_PK_AVAILABLE);
    byte[] sectorPK = "MySectorPublicKey".getBytes(StandardCharsets.UTF_8);
    sectorPublicKeyResult.setSectorPK(sectorPK);
    Mockito.when(port.getSectorPublicKey(ArrayUtils.EMPTY_BYTE_ARRAY)).thenReturn(sectorPublicKeyResult);

    byte[] result = restrictedIdService110.getSectorPublicKey(ArrayUtils.EMPTY_BYTE_ARRAY);
    Assertions.assertArrayEquals(sectorPublicKeyResult.getSectorPK(), result);

    sectorPublicKeyResult.setReturnCode(GetSectorPublicKeyReturnCodeType.FAILURE_INTERNAL_ERROR);
    GovManagementException govManagementException = Assertions.assertThrows(GovManagementException.class,
                                                                            () -> restrictedIdService110.getSectorPublicKey(ArrayUtils.EMPTY_BYTE_ARRAY));
    Assertions.assertEquals(GlobalManagementCodes.EC_UNEXPECTED_ERROR,
                            govManagementException.getManagementMessage().getCode());
    Assertions.assertEquals("getSectorPublicKey returned " + GetSectorPublicKeyReturnCodeType.FAILURE_INTERNAL_ERROR,
                            govManagementException.getManagementMessage().getDetails());
  }
}

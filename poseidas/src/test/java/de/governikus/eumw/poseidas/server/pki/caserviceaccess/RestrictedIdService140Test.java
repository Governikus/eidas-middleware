package de.governikus.eumw.poseidas.server.pki.caserviceaccess;

import java.net.URL;
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
import de.governikus.eumw.poseidas.services.restricted.id.wsdl.v1_4_0.ConditionalBinaryType;
import de.governikus.eumw.poseidas.services.restricted.id.wsdl.v1_4_0.ConditionalSectorPK;
import de.governikus.eumw.poseidas.services.restricted.id.wsdl.v1_4_0.ConditionalStringType;
import de.governikus.eumw.poseidas.services.restricted.id.wsdl.v1_4_0.GetBlockListRequest;
import de.governikus.eumw.poseidas.services.restricted.id.wsdl.v1_4_0.GetBlockListResult;
import de.governikus.eumw.poseidas.services.restricted.id.wsdl.v1_4_0.GetBlockListReturnCodeType;
import de.governikus.eumw.poseidas.services.restricted.id.wsdl.v1_4_0.GetSectorPublicKeyRequest;
import de.governikus.eumw.poseidas.services.restricted.id.wsdl.v1_4_0.GetSectorPublicKeyResult;
import de.governikus.eumw.poseidas.services.restricted.id.wsdl.v1_4_0.GetSectorPublicKeyReturnCodeType;
import de.governikus.eumw.poseidas.services.restricted.id.wsdl.v1_4_0.RestrictedIdWebService_1_4_0;
import de.governikus.eumw.utils.xml.XmlHelper;


@ExtendWith(MockitoExtension.class)
class RestrictedIdService140Test
{

  public static final byte[] SECTOR_PK = "MySectorPublicKey".getBytes(StandardCharsets.UTF_8);

  public static final URL schemaUrl = RestrictedIdService140Test.class.getResource("/META-INF/wsdl/CA-Services-1-4-0/part-3/restrictedID/BasicTypes_DV_RestrictedIdentification.xsd");

  @Mock
  PKIServiceConnector connector;

  @Mock
  RestrictedIdWebService_1_4_0 port;

  private RestrictedIdService140 restrictedIdService140;


  @BeforeEach
  void setUp() throws Exception
  {
    restrictedIdService140 = new RestrictedIdService140(connector, "https://riURL");
    restrictedIdService140.setPort(port);
  }

  @Test
  void testBlResult() throws Exception
  {

    GetBlockListResult blockListResult = new GetBlockListResult();
    blockListResult.setReturnCode(GetBlockListReturnCodeType.OK_NO_UPDATE_NEEDED);
    Mockito.when(port.getBlockList(Mockito.any(GetBlockListRequest.class))).thenReturn(blockListResult);

    // No Update Needed
    RestrictedIdService.BlackListResult result = restrictedIdService140.getBlacklistResult(null, null);
    Assertions.assertEquals(RestrictedIdService140.NO_NEW_DATA, result);

    // Delta List
    blockListResult.setReturnCode(GetBlockListReturnCodeType.OK_LIST_AVAILABLE);
    ConditionalBinaryType optionalBinaryType = new ConditionalBinaryType();
    optionalBinaryType.setBinary(ArrayUtils.EMPTY_BYTE_ARRAY);
    blockListResult.setDeltaListAddedItems(optionalBinaryType);
    blockListResult.setDeltaListRemovedItems(optionalBinaryType);
    Mockito.when(port.getBlockList(Mockito.any(GetBlockListRequest.class))).thenReturn(blockListResult);
    result = restrictedIdService140.getBlacklistResult(ArrayUtils.EMPTY_BYTE_ARRAY, null);
    Assertions.assertArrayEquals(result.getDeltaAdded(), optionalBinaryType.getBinary());
    Assertions.assertArrayEquals(result.getDeltaRemoved(), optionalBinaryType.getBinary());

    // Complete List
    blockListResult.setReturnCode(GetBlockListReturnCodeType.OK_LIST_AVAILABLE);
    ConditionalStringType optionalStringType = new ConditionalStringType();
    optionalStringType.setString("http//downloadBL");
    blockListResult.setCompleteListURL(optionalStringType);
    Mockito.when(port.getBlockList(Mockito.any(GetBlockListRequest.class))).thenReturn(blockListResult);
    result = restrictedIdService140.getBlacklistResult(null, null);
    Assertions.assertEquals("http//downloadBL", result.getUri());

    // GovManagementException
    blockListResult.setReturnCode(GetBlockListReturnCodeType.FAILURE_INTERNAL_ERROR);
    Mockito.when(port.getBlockList(Mockito.any(GetBlockListRequest.class))).thenReturn(blockListResult);
    GovManagementException govManagementException = Assertions.assertThrows(GovManagementException.class,
                                                                            () -> restrictedIdService140.getBlacklistResult(null,
                                                                                                                            null));
    Assertions.assertEquals(GlobalManagementCodes.EC_UNEXPECTED_ERROR,
                            govManagementException.getManagementMessage().getCode());
    Assertions.assertEquals("getBlackList for returned " + GetBlockListReturnCodeType.FAILURE_INTERNAL_ERROR,
                            govManagementException.getManagementMessage().getDetails());
  }

  @Test
  void testGetSectorPublicKey() throws Exception
  {
    GetSectorPublicKeyResult sectorPublicKeyResult = new GetSectorPublicKeyResult();
    sectorPublicKeyResult.setReturnCode(GetSectorPublicKeyReturnCodeType.OK_PK_AVAILABLE);
    ConditionalSectorPK conditionalSectorPK = new ConditionalSectorPK();
    conditionalSectorPK.setSectorPK(SECTOR_PK);
    sectorPublicKeyResult.setSectorPK(conditionalSectorPK);
    Mockito.when(port.getSectorPublicKey(Mockito.any(GetSectorPublicKeyRequest.class)))
           .thenReturn(sectorPublicKeyResult);

    byte[] result = restrictedIdService140.getSectorPublicKey(ArrayUtils.EMPTY_BYTE_ARRAY);
    Assertions.assertArrayEquals(sectorPublicKeyResult.getSectorPK().getSectorPK(), result);

    sectorPublicKeyResult.setReturnCode(GetSectorPublicKeyReturnCodeType.FAILURE_INTERNAL_ERROR);
    GovManagementException govManagementException = Assertions.assertThrows(GovManagementException.class,
                                                                            () -> restrictedIdService140.getSectorPublicKey(ArrayUtils.EMPTY_BYTE_ARRAY));
    Assertions.assertEquals(GlobalManagementCodes.EC_UNEXPECTED_ERROR,
                            govManagementException.getManagementMessage().getCode());
    Assertions.assertEquals("getSectorPublicKey returned " + GetSectorPublicKeyReturnCodeType.FAILURE_INTERNAL_ERROR,
                            govManagementException.getManagementMessage().getDetails());
  }

  @Test
  void testGetBlocklistSchemaConformance()
  {
    Mockito.when(port.getBlockList(Mockito.any(GetBlockListRequest.class))).thenAnswer(invocation -> {
      String requestString = XmlHelper.marshalObject(invocation.getArgument(0));
      XmlHelper.validateWithSchema(requestString, schemaUrl);
      GetBlockListResult getBlockListResult = new GetBlockListResult();
      getBlockListResult.setReturnCode(GetBlockListReturnCodeType.OK_NO_UPDATE_NEEDED);
      return getBlockListResult;
    });
    Assertions.assertDoesNotThrow(() -> restrictedIdService140.getBlacklistResult(null, SECTOR_PK));
    Assertions.assertDoesNotThrow(() -> restrictedIdService140.getBlacklistResult("deltabase".getBytes(StandardCharsets.UTF_8),
                                                                                  SECTOR_PK));
  }

  @Test
  void testGetSectorPublicKeySchemaConformance()
  {
    Mockito.when(port.getSectorPublicKey(Mockito.any(GetSectorPublicKeyRequest.class))).thenAnswer(invocation -> {
      String requestString = XmlHelper.marshalObject(invocation.getArgument(0));
      XmlHelper.validateWithSchema(requestString, schemaUrl);
      GetSectorPublicKeyResult getSectorPublicKeyResult = new GetSectorPublicKeyResult();
      getSectorPublicKeyResult.setReturnCode(GetSectorPublicKeyReturnCodeType.OK_PK_AVAILABLE);
      ConditionalSectorPK sectorPK = new ConditionalSectorPK();
      sectorPK.setSectorPK("key".getBytes(StandardCharsets.UTF_8));
      getSectorPublicKeyResult.setSectorPK(sectorPK);
      return getSectorPublicKeyResult;
    });
    Assertions.assertDoesNotThrow(() -> restrictedIdService140.getSectorPublicKey(SECTOR_PK));
  }
}

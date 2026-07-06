package de.governikus.eumw.poseidas.server.pki.caserviceaccess;

import java.net.URL;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import de.governikus.eumw.poseidas.services.passive.auth.wsdl.v1_4_0.ConditionalBinaryType;
import de.governikus.eumw.poseidas.services.passive.auth.wsdl.v1_4_0.GetDefectListRequest;
import de.governikus.eumw.poseidas.services.passive.auth.wsdl.v1_4_0.GetDefectListResult;
import de.governikus.eumw.poseidas.services.passive.auth.wsdl.v1_4_0.GetMasterListRequest;
import de.governikus.eumw.poseidas.services.passive.auth.wsdl.v1_4_0.GetMasterListResult;
import de.governikus.eumw.poseidas.services.passive.auth.wsdl.v1_4_0.GetReturnCodeType;
import de.governikus.eumw.poseidas.services.passive.auth.wsdl.v1_4_0.PassiveAuthWebService_1_4_0;
import de.governikus.eumw.utils.xml.XmlHelper;


@ExtendWith(MockitoExtension.class)
class PassiveAuthServiceTest
{

  public static final URL schemaUrl = RestrictedIdService140Test.class.getResource("/META-INF/wsdl/CA-Services-1-4-0/part-3/passiveAuth/BasicTypes_DV_PassiveAuth.xsd");

  @Mock
  PKIServiceConnector connector;

  @Mock
  PassiveAuthWebService_1_4_0 port;

  private PassiveAuthService passiveAuthService;


  @BeforeEach
  void setUp() throws Exception
  {
    passiveAuthService = new PassiveAuthService(connector, "https://riURL");
    passiveAuthService.setPort(port);
  }

  @Test
  void testGetMasterListSchemaConformance()
  {
    Mockito.when(port.getMasterList(Mockito.any(GetMasterListRequest.class))).thenAnswer(invocation -> {
      String requestString = XmlHelper.marshalObject(invocation.getArgument(0));
      XmlHelper.validateWithSchema(requestString, schemaUrl);
      GetMasterListResult getMasterListResult = new GetMasterListResult();
      getMasterListResult.setReturnCode(GetReturnCodeType.OK_LIST_AVAILABLE);
      ConditionalBinaryType masterList = new ConditionalBinaryType();
      masterList.setBinary("masterlist".getBytes(StandardCharsets.UTF_8));
      getMasterListResult.setMasterList(masterList);
      return getMasterListResult;
    });
    Assertions.assertDoesNotThrow(() -> passiveAuthService.getMasterList());
  }

  @Test
  void testGetDefectListSchemaConformance()
  {
    Mockito.when(port.getDefectList(Mockito.any(GetDefectListRequest.class))).thenAnswer(invocation -> {
      String requestString = XmlHelper.marshalObject(invocation.getArgument(0));
      XmlHelper.validateWithSchema(requestString, schemaUrl);
      GetDefectListResult getDefectListResult = new GetDefectListResult();
      getDefectListResult.setReturnCode(GetReturnCodeType.OK_LIST_AVAILABLE);
      ConditionalBinaryType masterList = new ConditionalBinaryType();
      masterList.setBinary("masterlist".getBytes(StandardCharsets.UTF_8));
      getDefectListResult.setDefectList(masterList);
      return getDefectListResult;
    });
    Assertions.assertDoesNotThrow(() -> passiveAuthService.getDefectList());
  }

}

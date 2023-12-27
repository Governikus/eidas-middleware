/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardbase.npa;

import java.io.IOException;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import de.governikus.eumw.poseidas.cardbase.Hex;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.SecurityInfos;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.si.ChipAuthenticationDomainParameterInfo;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.si.ChipAuthenticationInfo;


class InfoSelectorTest
{

  private static final byte[] newEFCardAccess = Hex.parse("31820110300d060804007f00070202020201023012060a04007f000702020302020201020201413012060a04007f0007020203020202010302014a3012060a04007f0007020204020202010202010d301b060b04007f000702020b010203300902010102010002010102014a301c060904007f000702020302300c060704007f0007010202010d020141301c060904007f000702020302300c060704007f0007010202010d02014a302a060804007f0007020206161e687474703a2f2f6273692e62756e642e64652f6369662f6e70612e786d6c303e060804007f000702020831323012060a04007f00070202030202020102020145301c060904007f000702020302300c060704007f0007010202010d020145");

  private static final byte[] oldEFCardAccess = Hex.parse("3181c13012060a04007f0007020204020202010202010d300d060804007f00070202020201023012060a04007f00070202030202020102020129301c060904007f000702020302300c060704007f0007010202010d020129303e060804007f000702020831323012060a04007f0007020203020202010202012d301c060904007f000702020302300c060704007f0007010202010d02012d302a060804007f0007020206161e687474703a2f2f6273692e62756e642e64652f6369662f6e70612e786d6c");

  private static final byte[] efCardAccessWithCa2And3SameKeyId = Hex.parse("31820110300d060804007f00070202020201023012060a04007f000702020302020201020201413012060a04007f000702020302020201030201413012060a04007f0007020204020202010202010d301b060b04007f000702020b010203300902010102010002010102014a301c060904007f000702020302300c060704007f0007010202010d020141301c060904007f000702020302300c060704007f0007010202010d02014a302a060804007f0007020206161e687474703a2f2f6273692e62756e642e64652f6369662f6e70612e786d6c303e060804007f000702020831323012060a04007f00070202030202020102020145301c060904007f000702020302300c060704007f0007010202010d020145");

  private static final byte[] efCardAccessWithCa2And3SameKeyIdReverseOrder = Hex.parse("31820110300d060804007f00070202020201023012060a04007f000702020302020201030201413012060a04007f000702020302020201020201413012060a04007f0007020204020202010202010d301b060b04007f000702020b010203300902010102010002010102014a301c060904007f000702020302300c060704007f0007010202010d020141301c060904007f000702020302300c060704007f0007010202010d02014a302a060804007f0007020206161e687474703a2f2f6273692e62756e642e64652f6369662f6e70612e786d6c303e060804007f000702020831323012060a04007f00070202030202020102020145301c060904007f000702020302300c060704007f0007010202010d020145");

  private static final byte[] efCardAccessWithoutCa2 = Hex.parse("31820110300d060804007f00070202020201023012060a04007f000702020302020201010201413012060a04007f0007020203020202010302014a3012060a04007f0007020204020202010202010d301b060b04007f000702020b010203300902010102010002010102014a301c060904007f000702020302300c060704007f0007010202010d020141301c060904007f000702020302300c060704007f0007010202010d02014a302a060804007f0007020206161e687474703a2f2f6273692e62756e642e64652f6369662f6e70612e786d6c303e060804007f000702020831323012060a04007f00070202030202020102020145301c060904007f000702020302300c060704007f0007010202010d020145");

  private static final byte[] efCardAccessWithUnknownCurveId = Hex.parse("3181c13012060a04007f0007020204020202010202010d300d060804007f00070202020201023012060a04007f00070202030202020102020129301c060904007f000702020302300c060704007f00070102020142020129303e060804007f000702020831323012060a04007f0007020203020202010202012d301c060904007f000702020302300c060704007f0007010202010d02012d302a060804007f0007020206161e687474703a2f2f6273692e62756e642e64652f6369662f6e70612e786d6c");

  private static final byte[] efCardAccessWithExplicitDomainParameters = Hex.parse("3181e53012060a04007f0007020204020202010202010d300d060804007f00070202020201023012060a04007f000702020302020201020201293040060904007F000702020302303006072a8648ce3d02013025020101300D06072a8648ce3d01010202008030060401000401000403040840020102020101020129303e060804007f000702020831323012060a04007f0007020203020202010202012d301c060904007f000702020302300c060704007f0007010202010d02012d302a060804007f0007020206161e687474703a2f2f6273692e62756e642e64652f6369662f6e70612e786d6c");

  private static Stream<byte[]> parameterSource()
  {
    return Stream.of(newEFCardAccess,
                     oldEFCardAccess,
                     efCardAccessWithCa2And3SameKeyId,
                     efCardAccessWithCa2And3SameKeyIdReverseOrder);
  }

  private static Stream<byte[]> parameterSourceUnsupported()
  {
    return Stream.of(efCardAccessWithUnknownCurveId, efCardAccessWithExplicitDomainParameters);
  }

  @ParameterizedTest
  @MethodSource("parameterSource")
  void testNewEFCardAccess(byte[] source) throws IOException
  {
    SecurityInfos efCardAccess = new SecurityInfos();
    efCardAccess.decode(source);

    List<ChipAuthenticationInfo> caInfoList = efCardAccess.getChipAuthenticationInfo();
    List<ChipAuthenticationDomainParameterInfo> caDomParamList = efCardAccess.getChipAuthenticationDomainParameterInfo();

    InfoSelector.ChipAuthenticationData caData = InfoSelector.selectCAData(caInfoList, caDomParamList);
    Assertions.assertEquals(2, caData.getCaInfo().getVersion());
  }

  @Test
  void testEFCardAccessNoCa2() throws IOException
  {
    SecurityInfos efCardAccess = new SecurityInfos();
    efCardAccess.decode(efCardAccessWithoutCa2);

    List<ChipAuthenticationInfo> caInfoList = efCardAccess.getChipAuthenticationInfo();
    List<ChipAuthenticationDomainParameterInfo> caDomParamList = efCardAccess.getChipAuthenticationDomainParameterInfo();

    Assertions.assertThrows(Exception.class, () -> InfoSelector.selectCAData(caInfoList, caDomParamList));
  }

  @ParameterizedTest
  @MethodSource("parameterSourceUnsupported")
  void testEFCardAccessUnsupported() throws IOException
  {
    SecurityInfos efCardAccess = new SecurityInfos();
    efCardAccess.decode(efCardAccessWithExplicitDomainParameters);

    List<ChipAuthenticationInfo> caInfoList = efCardAccess.getChipAuthenticationInfo();
    List<ChipAuthenticationDomainParameterInfo> caDomParamList = efCardAccess.getChipAuthenticationDomainParameterInfo();

    Assertions.assertNull(InfoSelector.selectCAData(caInfoList, caDomParamList));
  }
}

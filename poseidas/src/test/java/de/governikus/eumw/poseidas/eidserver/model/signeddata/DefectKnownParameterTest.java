package de.governikus.eumw.poseidas.eidserver.model.signeddata;

import java.io.InputStream;
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.google.common.io.ByteStreams;


class DefectKnownParameterTest
{


  @Test
  void testDefectListWithCertReplacementElement() throws Exception
  {
    byte[] defectListAsBytes;

    try (
      InputStream resourceAsStream = DefectKnownParameterTest.class.getResourceAsStream("/defectList/defectListWithCertReplaced.bin"))
    {
      defectListAsBytes = ByteStreams.toByteArray(resourceAsStream);
    }

    DefectList defectList = new DefectList(defectListAsBytes);

    List<Defect> defects = defectList.getDefects();

    List<Defect> certReplacedDefectList = defects.stream()
                                                 .filter(defect -> defect.containsKnownDefectsOfType(DefectKnown.DefectType.ID_CERT_REPLACED))
                                                 .toList();

    Assertions.assertEquals(1, certReplacedDefectList.size());
    Defect certReplacedDefect = certReplacedDefectList.get(0);
    List<DefectKnown> knownDefectsOfType = certReplacedDefect.getKnownDefectsOfType(DefectKnown.DefectType.ID_CERT_REPLACED);
    Assertions.assertEquals(1, knownDefectsOfType.size());
    DefectKnown defectKnown = knownDefectsOfType.get(0);
    X509Certificate replacedCertificate = defectKnown.getParameter().getReplacedCertificate();

    Assertions.assertNotNull(replacedCertificate);

    Assertions.assertEquals(BigInteger.valueOf(322L), replacedCertificate.getSerialNumber());
  }
}

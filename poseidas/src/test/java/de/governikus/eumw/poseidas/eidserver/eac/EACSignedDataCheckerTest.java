package de.governikus.eumw.poseidas.eidserver.eac;

import static org.junit.Assert.assertNull;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.boot.test.context.SpringBootTest;

import de.governikus.eumw.poseidas.SpringApplicationContextHelper;
import de.governikus.eumw.poseidas.cardbase.Hex;
import de.governikus.eumw.poseidas.eidserver.crl.CertificationRevocationListImpl;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationService;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationTestHelper;
import de.governikus.eumw.utils.key.SecurityProvider;

@SpringBootTest(properties = {"poseidas.snmp.agentport=10161"})
class EACSignedDataCheckerTest
{

  private static CertificateFactory cf;

  @BeforeAll
  static void init() throws CertificateException
  {
    cf = CertificateFactory.getInstance("X509", SecurityProvider.BOUNCY_CASTLE_PROVIDER);
  }

  @BeforeEach
  void initSingle() throws Exception
  {
    ConfigurationService cs = SpringApplicationContextHelper.getConfigurationService();
    cs.saveConfiguration(ConfigurationTestHelper.createValidConfiguration(), false);
    X509Certificate masterListTrustAnchor = (X509Certificate)cf.generateCertificate(ConfigurationTestHelper.class.getResourceAsStream("/TEST_csca_germany.cer"));
    if (!CertificationRevocationListImpl.isInitialized())
    {
      CertificationRevocationListImpl.initialize(Set.of(masterListTrustAnchor), cs);
    }
  }

  @Test
  void testSuccess() throws Exception
  {
    X509Certificate cert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(Base64.getDecoder()
                                                                                                  .decode("MIIEsjCCBBagAwIBAgICBPUwCgYIKoZIzj0EAwQwRjELMAkGA1UEBhMCREUxDTALBgNVBAoMBGJ1bmQxDDAKBgNVBAsMA2JzaTEaMBgGA1UEAwwRVEVTVCBjc2NhLWdlcm1hbnkwHhcNMjExMDA3MDc1OTAyWhcNMzIwNTA3MjM1OTU5WjBtMQswCQYDVQQGEwJERTEdMBsGA1UECgwUQnVuZGVzZHJ1Y2tlcmVpIEdtYkgxDTALBgNVBAUTBDAxMDgxMDAuBgNVBAMMJ1RFU1QgRG9jdW1lbnQgU2lnbmVyIElkZW50aXR5IERvY3VtZW50czCCAbUwggFNBgcqhkjOPQIBMIIBQAIBATA8BgcqhkjOPQEBAjEAjLkegqM4bSgPXW9+UOZB3xUvcQntVFa0ErHaGX+3ESOs06cpkB0acYdHABMxB+xTMGQEMHvDgsY9jBUMPHIICs4Fr6DCvqKOT7InhxORZe+6kfkPiqWBSlA61OsEqMfdIs4oJgQwBKjH3SLOKCaLObVUFvBEfC+3feEH3NKmLogOpT7rYtV8tDkCldvJlDq3hpb6UEwRBGEEHRxk8GjPRf+ipjqBt8E/a4hHo+d+8U/j23/K/gy9EOjoJuA0NtZGqu+HsuJH1K8eir4ddSD5wqRcseuOlc/VUmK3Cyn+7Fhk4ZwFT/mRKSgORkYhd5GBEUKCA0EmPFMVAjEAjLkegqM4bSgPXW9+UOZB3xUvcQntVFazHxZubKwEJafPOrava3/DEDuIMgLpBGVlAgEBA2IABA3N5BZnRi1wEtqHk/GO2DNrmKrYUQDcfDi9eYOR2MZhjEZ+KK/guADIggcu4vSDTij7flVLDT1WpenMMqtf9/j7Dg3yOA8aQQgdaw3aQIMSfC1xL+FndSUj9E1Ruqz83aOCAW0wggFpMB8GA1UdIwQYMBaAFOT5NO5e2Y1hw/LvGknykIAdCPu5MB0GA1UdDgQWBBSbh4oRjoNVXrDg80r8v+R80HxhdjAOBgNVHQ8BAf8EBAMCB4AwKwYDVR0QBCQwIoAPMjAyMTEwMDcwNzU5MDJagQ8yMDIyMDUwNzIzNTk1OVowFgYDVR0gBA8wDTALBgkEAH8ABwMBAQEwLQYDVR0RBCYwJIISYnVuZGVzZHJ1Y2tlcmVpLmRlpA4wDDEKMAgGA1UEBwwBRDBRBgNVHRIESjBIgRhjc2NhLWdlcm1hbnlAYnNpLmJ1bmQuZGWGHGh0dHBzOi8vd3d3LmJzaS5idW5kLmRlL2NzY2GkDjAMMQowCAYDVQQHDAFEMBkGB2eBCAEBBgIEDjAMAgEAMQcTAUETAklEMDUGA1UdHwQuMCwwKqAooCaGJGh0dHA6Ly93d3cuYnNpLmJ1bmQuZGUvdGVzdF9jc2NhX2NybDAKBggqhkjOPQQDBAOBiQAwgYUCQQChTWxsAhIRE67KiQNC5jjwZtw1rGhs6CQLQmY1bwFPLvwDJ2dfanshiE3lUYTiElWa7EIYTIQn9GK0eIOOFATLAkAWHop5XlG3wYicX8xqoGUac/348uQrwoRuAd9nELw+zNFX3XreASe4cTUubYpyPZ5m/Yej6MHxoaf1H5clp+/X")));
    EACSignedDataChecker checker = new EACSignedDataChecker(List.of(cert), "");
    assertNotNull(checker.checkSignedData(Hex.parse("308208ee06092a864886f70d010702a08208df308208db020103310f300d06096086480165030402020500308202cd060804007f0007030201a08202bf048202bb318202b7300d060804007f00070202020201023012060a04007f000702020302020201020201413012060a04007f0007020203020202010302014a3012060a04007f0007020204020202010202010d3012060a04007f0007020204060202010202010d3017060a04007f0007020205020330090201010201430101ff3017060a04007f0007020205020330090201010201440101003019060904007f000702020502300c060704007f0007010202010d301b060b04007f000702020b010203300902010102010002010102014a301c060904007f000702020302300c060704007f0007010202010d020141301c060904007f000702020302300c060704007f0007010202010d02014a302a060804007f0007020206161e687474703a2f2f6273692e62756e642e64652f6369662f6e70612e786d6c3062060904007f0007020201023052300c060704007f0007010202010d034200042a5500dcd0884c60ba95bb583e28500f95c9ac67f0cda44f3c53c4255ec6d75a096534a345e78b3b8d69afd6fff0c9934531e72f8b76ad75b1aa58020afc5c3d02010d3062060904007f0007020201023052300c060704007f0007010202010d03420004326fef66d0f1691ff70f971fca96c4577f9e924531c3e793f76ee8c1de5b44674f2246994411a86e746e5545a35c5116737cd2aaa60eec5a7b166ab89575a02c0201413081bb060a04007f000702020103023081a73081a4305e060904007f0007010102033051300c060704007f0007010202010d0441045f5cb7d0ac1d1e0852b409914f9a5d74bef88213ddf341d05fd091c37c7c8e454b94fc146c8c56cbd695d45f8c2c21bd166b07d5febdc9db3c0fdbc0876af128034200045f5cb7d0ac1d1e0852b409914f9a5d74bef88213ddf341d05fd091c37c7c8e454b94fc146c8c56cbd695d45f8c2c21bd166b07d5febdc9db3c0fdbc0876af128300382014aa08204b6308204b230820416a003020102020204f5300a06082a8648ce3d0403043046310b3009060355040613024445310d300b060355040a0c0462756e64310c300a060355040b0c03627369311a301806035504030c115445535420637363612d6765726d616e79301e170d3231313030373037353930325a170d3332303530373233353935395a306d310b3009060355040613024445311d301b060355040a0c1442756e646573647275636b6572656920476d6248310d300b06035504051304303130383130302e06035504030c275445535420446f63756d656e74205369676e6572204964656e7469747920446f63756d656e7473308201b53082014d06072a8648ce3d020130820140020101303c06072a8648ce3d01010231008cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53306404307bc382c63d8c150c3c72080ace05afa0c2bea28e4fb22787139165efba91f90f8aa5814a503ad4eb04a8c7dd22ce2826043004a8c7dd22ce28268b39b55416f0447c2fb77de107dcd2a62e880ea53eeb62d57cb4390295dbc9943ab78696fa504c110461041d1c64f068cf45ffa2a63a81b7c13f6b8847a3e77ef14fe3db7fcafe0cbd10e8e826e03436d646aaef87b2e247d4af1e8abe1d7520f9c2a45cb1eb8e95cfd55262b70b29feec5864e19c054ff99129280e4646217791811142820341263c53150231008cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565020101036200040dcde41667462d7012da8793f18ed8336b98aad85100dc7c38bd798391d8c6618c467e28afe0b800c882072ee2f4834e28fb7e554b0d3d56a5e9cc32ab5ff7f8fb0e0df2380f1a41081d6b0dda4083127c2d712fe167752523f44d51baacfcdda382016d30820169301f0603551d23041830168014e4f934ee5ed98d61c3f2ef1a49f290801d08fbb9301d0603551d0e041604149b878a118e83555eb0e0f34afcbfe47cd07c6176300e0603551d0f0101ff040403020780302b0603551d1004243022800f32303231313030373037353930325a810f32303232303530373233353935395a30160603551d20040f300d300b060904007f000703010101302d0603551d1104263024821262756e646573647275636b657265692e6465a40e300c310a300806035504070c014430510603551d12044a30488118637363612d6765726d616e79406273692e62756e642e6465861c68747470733a2f2f7777772e6273692e62756e642e64652f63736361a40e300c310a300806035504070c01443019060767810801010602040e300c02010031071301411302494430350603551d1f042e302c302aa028a0268624687474703a2f2f7777772e6273692e62756e642e64652f746573745f637363615f63726c300a06082a8648ce3d04030403818900308185024100a14d6c6c02121113aeca890342e638f066dc35ac686ce8240b4266356f014f2efc0327675f6a7b21884de55184e212559aec42184c8427f462b478838e1404cb0240161e8a795e51b7c1889c5fcc6aa0651a73fdf8f2e42bc2846e01df6710bc3eccd157dd7ade0127b871352e6d8a723d9e66fd87a3e8c1f1a1a7f51f9725a7efd73182013830820134020101304c3046310b3009060355040613024445310d300b060355040a0c0462756e64310c300a060355040b0c03627369311a301806035504030c115445535420637363612d6765726d616e79020204f5300d06096086480165030402020500a05a301706092a864886f70d010903310a060804007f0007030201303f06092a864886f70d01090431320430982db68e9a226fb6a5ec7fe2cb30cfbf0343c80807a07c921ce62fe8297d3b9b1e9f8662fe9c13228a270e3644d785b5300c06082a8648ce3d0403030500046630640230156d2947525371c7eba7aa63a54a0c9f72a59a390f6ff2db9bfd21b1f8430531770d44b7b49ed5a5723e4cb7ccc3e1080230168d2f8efbe8942b18baf0c5474159204d881ad0ca1ea89c312556dd8fe9a17af5d0ffb7147279d3935737afe909ec0ea100")));
  }

  @ParameterizedTest
  @MethodSource("parameterSource")
  void testFailure(String certString, String cardSecurity) throws Exception
  {
    X509Certificate cert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(Base64.getDecoder()
                                                                                                  .decode(certString)));
    EACSignedDataChecker checker = new EACSignedDataChecker(List.of(cert), "");
    assertNull(checker.checkSignedData(Hex.parse(cardSecurity)));
  }

  private static Stream<Arguments> parameterSource()
  {
    return Stream.of(// not brainpool
                     Arguments.of("MIIBHjCBxaADAgECAgYBjBFo674wCgYIKoZIzj0EAwIwFjEUMBIGA1UEAwwLV3Vyc3RJc3N1ZXIwHhcNMjMxMTI3MTUzMjE3WhcNMzIwMzI3MTUzMjE3WjAXMRUwEwYDVQQDDAxXdXJzdFN1YmplY3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAR7I1u28N2p9bjeWypzSYB3SZgsBmBsHTL9NnZB3jxPHAFuZkcXu/dR1WEs6zWAjDBnwceWK95Hxpgb0ZHHRoKhMAoGCCqGSM49BAMCA0gAMEUCIQCbOIVAVTJrgtq1QSqeYnQrGNuvUUfcZarjVwbAAwX5nQIgL3UadhoHwCW+aBnIa79sGvTbnyazBcg/cieqYJ0IJ7Q=",
                                  "3082065206092a864886f70d010702a08206433082063f020103310d300b0609608648016503040201308203e0060804007f0007030201a08203d2048203ce318203ca3012060a04007f0007020204020202010202010d300d060804007f00070202020201023017060a04007f0007020205020330090201010201010101003021060904007f000702020502301406072a8648ce3d020106092b24030302080101073017060a04007f0007020205020330090201010201020101ff3012060a04007f00070202030202020102020129301c060904007f000702020302300c060704007f0007010202010d0201293062060904007f0007020201023052300c060704007f0007010202010d0342000419d4b7447788b0e1993db35500999627e739a4e5e35f02d8fb07d6122e76567f17758d7a3aa6943ef23e5e2909b3e8b31bfaa4544c2cbf1fb487f31ff239c8f80201293081a3060804007f00070202083181963012060a04007f0007020203020202010202012d301c060904007f000702020302300c060704007f0007010202010d02012d3062060904007f0007020201023052300c060704007f0007010202010d034200041ac6cae884a6c2b8461404150f54cd1150b21e862a4e5f21ce34290c741104bd1bf31ed91e085d7c630e8b4d10a8ae22bbb2898b44b52ea0f4cdadcf57cfba2502012d302a060804007f0007020206161e687474703a2f2f6273692e62756e642e64652f6369662f6e70612e786d6c308201e6060804007f0007020207308201d8300b0609608648016503040204308201c73021020101041c2ff0247f59dd3c646e314f03abb33ee91a586577ebdf48d3864ec34d3021020102041c37823963b71af0bf5698d1fdc30da2b7f9ece57cfa4959bee9d6d9943021020103041ce8b2a171dc1290a765f124aafe33061c08c918a1069dff5caf4c62b53021020104041cad81d20dbd4f5687fdb05e5037ec267609fde28c6036fdbdf2c8b4333021020105041ca90f28eb7a0fa0de83abf3293d14e0838b9c85fc7277cbb97737a32b3021020106041c712b8550e49a13c64dced4457e9a0f5a85dc26cd6a321596723005d63021020107041c42a8fa36b60887ed022cd3b6ecc255220fbe8cb3f607e416601fcaa63021020108041c6446e0a909967462b5c1117634f8a1b557ef74be3f606c1e94efae433021020109041c635d1017f4abc656b9fdddd7e0fbb1e992b7686e89485e6ab51b638b302102010d041c04db93544a64bc1245b10aab266386f08f8e89f72e1db178c172624d3021020111041caadee20557d41ab9969e962282caf25904475148d329d2f6b2f43e343021020112041c57ce396ca707b96fa37c580f693230e4d4aebb97293f0909489d95cb302102010a041c1880a259cdb497c15a7fdd1c9ac9490d7dc0d18743378603d43d1d4fa08201223082011e3081c5a0030201020206018c1168ebbe300a06082a8648ce3d04030230163114301206035504030c0b5775727374497373756572301e170d3233313132373135333231375a170d3332303332373135333231375a30173115301306035504030c0c57757273745375626a6563743059301306072a8648ce3d020106082a8648ce3d030107034200047b235bb6f0dda9f5b8de5b2a7349807749982c06606c1d32fd367641de3c4f1c016e664717bbf751d5612ceb35808c3067c1c7962bde47c6981bd191c74682a1300a06082a8648ce3d04030203480030450221009b38854055326b82dab5412a9e62742b18dbaf5147dc65aae35706c00305f99d02202f751a761a07c025be6819c86bbf6c1af4db9f26b305c83f7227aa609d0827b43182011f3082011b020101302030163114301206035504030c0b57757273744973737565720206018c1168ebbe300b0609608648016503040201a08192301706092a864886f70d010903310a060804007f0007030201301c06092a864886f70d010905310f170d3233313132373135333231385a302806092a864886f70d010934311b3019300b0609608648016503040201a10a06082a8648ce3d040302302f06092a864886f70d0109043122042009ab7f4ecd22f7b164acec325af673964d93d1457a57a50206b63ea738711f69300a06082a8648ce3d040302044630440220082d92cb14714776a89ebb7ad9988a57867dedd5ea418f6c9e85ac8e32b819e002205dfcf4ade996a077fbfd75f0f97dcce09b6ee336506334de9eb11fadafb313fa"),
                     // RSA (unsupported sigalg)
                     Arguments.of("MIIEqzCCApOgAwIBAgIGAYwRe63wMA0GCSqGSIb3DQEBCwUAMBYxFDASBgNVBAMMC1d1cnN0SXNzdWVyMB4XDTIzMTEyNzE1NTI0N1oXDTMyMDMyNzE1NTI0N1owFzEVMBMGA1UEAwwMV3Vyc3RTdWJqZWN0MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAjnXM8LOnNPJq5Z8G4Vv7mFX1wEfWi9shzLffTryPVf5axT5tZCNXD2VYTA7TFNfOsP3r/M6NEB8mtuyOV5f1f8tERSkjrIc7fdSTF54/khqNoahczCEV7fOR+b0uqR6x6qzA5k3QREwFVEcvqJB6D0SEeK3CH5TWNIloer10rQhbDLGbn1NLTpaHk9WR6ENeBM9i5xWKyYe6vZDq9UIDIcSZhltr8Ril/crV7iqtG4K9Fz1mIfHHLF5LrrRf1CdsRoDbHqQ21sXMsGY+gKECXX4bx2vsJDT8ld/iQxvFo/+Z+Byof/moCQsBDHS+RKRnysAns7bd8fVYTpS90D1uCUOH6BMokN/KsDVojH7weeaqSdQZuuj1VRhoXwFC1NsnpISvv/Ryu48geo9aoyf6pQipMAAOp6jeM+AhPOvVNoRM6P52HcWlGbLorellmfWFcr0ugHI5KCJYZx2rmju/ywypw4EsvyTPehgwJRNF3gVAGsueHfWEHXLLr50cWSkryz9TL9hlZrl70R8Bx2oKtKWTUZT7Z/Q+cTjSoW2BctVlKQYdm3al/5jvuREq815R4bvhPD2JTP+416AkaqWEUTxDdJYo5D5DH1CiHUqE2MHWitGiDUhmQE3cjqpOuBZLw3AiizLcNte3756fZkkSiXhR/qpnaXpRb3LMUmm1z/0CAwEAATANBgkqhkiG9w0BAQsFAAOCAgEAJfWW66mFSiobk8PDimu84pAi5ao0Xi9pyZXQaKNPN9Eq3mi5AUJjl8hOS58L5zfIZ54NmzdA1AD1z/t2z2yD66fszxaHRU/5EKjl1EpbGRDgPrYgtJas1d8O8ohQ96EbXY6X7o3BrACf2BHCbgzF1fcovRbS9ngo0hQqmQz49loWDIwqgJSrTZNjk8mo3KP4UrndoxgytNsYp6RtgtOLhTjRHksGGbhDYgpxxIG26CQDPiYYGLqn8xI7FuGPFw3+219FaCaUZH2lKK8+U06dsdL4a8w/9j6flZEruGvKHwJpmzx75jkjqAkgkK+GjGU5zN0eCx1UQJ5sRtlWf0FnXmLcz8yiSdVV3TjmjSzVXWCnpz27rS41h6r0ELJKkVy3h9RknESR2FG0rM6478EhHIuRzcc01CBOupr63OEzzQYS2Of7NqMW+QaplUI1syu08GrLrfyRZNRclG71w9yEaLXtxGlVOdjrG+unbjTfAIXrPqp6xpaKa1Vx0cVTwFi5iMt71oRF61VMYe0OugIIwKYqNXV3uAnRUugSipg0NxV9lSLZW/krRJ6gzAlbUD7ETeW5JuO0y0euYWtLGUqam5LMZ2xT7stJhRiVf+HcLigIzUpeYNvv25UwRSH4qMmL5KbCuiCg0hH2o69NtMq+AjDVPDVoVxi6uJPiloarANs=",
                                  "30820ba106092a864886f70d010702a0820b9230820b8e020103310d300b0609608648016503040201308203e0060804007f0007030201a08203d2048203ce318203ca3012060a04007f0007020204020202010202010d300d060804007f00070202020201023017060a04007f0007020205020330090201010201010101003021060904007f000702020502301406072a8648ce3d020106092b24030302080101073017060a04007f0007020205020330090201010201020101ff3012060a04007f00070202030202020102020129301c060904007f000702020302300c060704007f0007010202010d0201293062060904007f0007020201023052300c060704007f0007010202010d0342000419d4b7447788b0e1993db35500999627e739a4e5e35f02d8fb07d6122e76567f17758d7a3aa6943ef23e5e2909b3e8b31bfaa4544c2cbf1fb487f31ff239c8f80201293081a3060804007f00070202083181963012060a04007f0007020203020202010202012d301c060904007f000702020302300c060704007f0007010202010d02012d3062060904007f0007020201023052300c060704007f0007010202010d034200041ac6cae884a6c2b8461404150f54cd1150b21e862a4e5f21ce34290c741104bd1bf31ed91e085d7c630e8b4d10a8ae22bbb2898b44b52ea0f4cdadcf57cfba2502012d302a060804007f0007020206161e687474703a2f2f6273692e62756e642e64652f6369662f6e70612e786d6c308201e6060804007f0007020207308201d8300b0609608648016503040204308201c73021020101041c2ff0247f59dd3c646e314f03abb33ee91a586577ebdf48d3864ec34d3021020102041c37823963b71af0bf5698d1fdc30da2b7f9ece57cfa4959bee9d6d9943021020103041ce8b2a171dc1290a765f124aafe33061c08c918a1069dff5caf4c62b53021020104041cad81d20dbd4f5687fdb05e5037ec267609fde28c6036fdbdf2c8b4333021020105041ca90f28eb7a0fa0de83abf3293d14e0838b9c85fc7277cbb97737a32b3021020106041c712b8550e49a13c64dced4457e9a0f5a85dc26cd6a321596723005d63021020107041c42a8fa36b60887ed022cd3b6ecc255220fbe8cb3f607e416601fcaa63021020108041c6446e0a909967462b5c1117634f8a1b557ef74be3f606c1e94efae433021020109041c635d1017f4abc656b9fdddd7e0fbb1e992b7686e89485e6ab51b638b302102010d041c04db93544a64bc1245b10aab266386f08f8e89f72e1db178c172624d3021020111041caadee20557d41ab9969e962282caf25904475148d329d2f6b2f43e343021020112041c57ce396ca707b96fa37c580f693230e4d4aebb97293f0909489d95cb302102010a041c1880a259cdb497c15a7fdd1c9ac9490d7dc0d18743378603d43d1d4fa08204af308204ab30820293a0030201020206018c117badf0300d06092a864886f70d01010b050030163114301206035504030c0b5775727374497373756572301e170d3233313132373135353234375a170d3332303332373135353234375a30173115301306035504030c0c57757273745375626a65637430820222300d06092a864886f70d01010105000382020f003082020a02820201008e75ccf0b3a734f26ae59f06e15bfb9855f5c047d68bdb21ccb7df4ebc8f55fe5ac53e6d6423570f65584c0ed314d7ceb0fdebfcce8d101f26b6ec8e5797f57fcb44452923ac873b7dd493179e3f921a8da1a85ccc2115edf391f9bd2ea91eb1eaacc0e64dd0444c0554472fa8907a0f448478adc21f94d63489687abd74ad085b0cb19b9f534b4e968793d591e8435e04cf62e7158ac987babd90eaf5420321c499865b6bf118a5fdcad5ee2aad1b82bd173d6621f1c72c5e4baeb45fd4276c4680db1ea436d6c5ccb0663e80a1025d7e1bc76bec2434fc95dfe2431bc5a3ff99f81ca87ff9a8090b010c74be44a467cac027b3b6ddf1f5584e94bdd03d6e094387e8132890dfcab035688c7ef079e6aa49d419bae8f55518685f0142d4db27a484afbff472bb8f207a8f5aa327faa508a930000ea7a8de33e0213cebd536844ce8fe761dc5a519b2e8ade96599f58572bd2e807239282258671dab9a3bbfcb0ca9c3812cbf24cf7a1830251345de05401acb9e1df5841d72cbaf9d1c59292bcb3f532fd86566b97bd11f01c76a0ab4a5935194fb67f43e7138d2a16d8172d56529061d9b76a5ff98efb9112af35e51e1bbe13c3d894cffb8d7a0246aa584513c43749628e43e431f50a21d4a84d8c1d68ad1a20d4866404ddc8eaa4eb8164bc370228b32dc36d7b7ef9e9f664912897851feaa67697a516f72cc5269b5cffd0203010001300d06092a864886f70d01010b0500038202010025f596eba9854a2a1b93c3c38a6bbce29022e5aa345e2f69c995d068a34f37d12ade68b901426397c84e4b9f0be737c8679e0d9b3740d400f5cffb76cf6c83eba7eccf1687454ff910a8e5d44a5b1910e03eb620b496acd5df0ef28850f7a11b5d8e97ee8dc1ac009fd811c26e0cc5d5f728bd16d2f67828d2142a990cf8f65a160c8c2a8094ab4d936393c9a8dca3f852b9dda31832b4db18a7a46d82d38b8538d11e4b0619b843620a71c481b6e824033e261818baa7f3123b16e18f170dfedb5f45682694647da528af3e534e9db1d2f86bcc3ff63e9f95912bb86bca1f02699b3c7be63923a8092090af868c6539ccdd1e0b1d54409e6c46d9567f41675e62dccfcca249d555dd38e68d2cd55d60a7a73dbbad2e3587aaf410b24a915cb787d4649c4491d851b4acceb8efc1211c8b91cdc734d4204eba9afadce133cd0612d8e7fb36a316f906a9954235b32bb4f06acbadfc9164d45c946ef5c3dc8468b5edc4695539d8eb1beba76e34df0085eb3eaa7ac6968a6b5571d1c553c058b988cb7bd68445eb554c61ed0eba0208c0a62a357577b809d152e8128a983437157d9522d95bf92b449ea0cc095b503ec44de5b926e3b4cb47ae616b4b194a9a9b92cc676c53eecb498518957fe1dc2e2808cd4a5e60dbefdb95304521f8a8c98be4a6c2ba20a0d211f6a3af4db4cabe0230d53c35685718bab893e29686ab00db318202e1308202dd020101302030163114301206035504030c0b57757273744973737565720206018c117badf0300b0609608648016503040201a08195301706092a864886f70d010903310a060804007f0007030201301c06092a864886f70d010905310f170d3233313132373135353234375a302b06092a864886f70d010934311e301c300b0609608648016503040201a10d06092a864886f70d01010b0500302f06092a864886f70d0109043122042009ab7f4ecd22f7b164acec325af673964d93d1457a57a50206b63ea738711f69300d06092a864886f70d01010b0500048202001ec9076614c983b290698920df8809f8e381038592a3e0bdbec92aca62eb5f43b3ced54a768b534912db54b9e8453f986ea878abf4b4352e73082a36f9db3328cb78bd9976bfc35324143456a5aac3eced5e8e8c57ee305ce654b3f3e68b01533a1d3a0cd8d4e4997de8bcf083f540027bd847027d3a8a6d678364cdc9f6031404803483022b8993856d84f14946983c0c5f89cff275542b5f67ce4451f10297c4c998f1aa89aab1ce8466f049e992545e218b372e1c4535ae11f2c66cc679b5fe4324b79eb554bdf181cc8da94decd5e543309916c4456c5bb09acc02a2d07f68422a209fa5f790ff0655d837bb9e7275689465d3418a098577d55a80c59d852a77feabf5139f4125f6497a20c5b65d6fe3b729880144f3d672cb0e51094cd4e54119c7905d01ed5e20ccdd27af5d3cfad74dbb2148e37a5c93d4e3614fb417b4743124243b8362a84621f29d4bab5113587f419fb9408ba8a623f19b1ec45b02f538791d3d89779172774f19b309b1bfbb246d2c7ceb9836397c6a2e68f3ae4e31eead91e316ece3b55dfd6139fd5354fa77108f82ba40f4acf543c68b3d57d9e160325ff657bf34432dd4136ceaa4b0c94736ce2500f01300cd8029aaba0deb7fad8ecdcc9388a409926a1b001abffda5af912931f44535865aa97e31960b22bb8973f782bc4db23a891c7b39b441b6e58cd4f9160956c4c57765a37d102b"));
  }
}

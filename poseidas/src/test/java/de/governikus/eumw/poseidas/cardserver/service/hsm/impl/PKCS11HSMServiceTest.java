package de.governikus.eumw.poseidas.cardserver.service.hsm.impl;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.jupiter.api.Test;


class PKCS11HSMServiceTest
{

  @Test
  void testIsRscAlias()
  {
    assertFalse(PKCS11HSMService.isRscAlias(null));
    assertFalse(PKCS11HSMService.isRscAlias(""));
    assertFalse(PKCS11HSMService.isRscAlias("123"));
    assertTrue(PKCS11HSMService.isRscAlias("RSC02"));
    assertFalse(PKCS11HSMService.isRscAlias("RSC002"));
    assertTrue(PKCS11HSMService.isRscAlias("WURSTRSC01"));
    assertFalse(PKCS11HSMService.isRscAlias("HIRSCH00001"));
  }
}

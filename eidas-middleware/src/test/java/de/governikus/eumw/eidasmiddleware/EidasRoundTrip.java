/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.eidasmiddleware;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactoryConfigurationError;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.xmlsec.encryption.support.EncryptionException;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.xml.sax.SAXException;

import de.governikus.eumw.eidascommon.ErrorCodeException;
import de.governikus.eumw.eidascommon.Utils;
import de.governikus.eumw.eidascommon.Utils.X509KeyPair;
import de.governikus.eumw.eidasstarterkit.Constants;
import de.governikus.eumw.eidasstarterkit.EidasAttribute;
import de.governikus.eumw.eidasstarterkit.EidasEncrypter;
import de.governikus.eumw.eidasstarterkit.EidasLoaEnum;
import de.governikus.eumw.eidasstarterkit.EidasNameIdType;
import de.governikus.eumw.eidasstarterkit.EidasNaturalPersonAttributes;
import de.governikus.eumw.eidasstarterkit.EidasRequest;
import de.governikus.eumw.eidasstarterkit.EidasResponse;
import de.governikus.eumw.eidasstarterkit.EidasSaml;
import de.governikus.eumw.eidasstarterkit.EidasSigner;
import de.governikus.eumw.eidasstarterkit.EidasTransientNameId;
import de.governikus.eumw.eidasstarterkit.person_attributes.EidasPersonAttributes;
import de.governikus.eumw.eidasstarterkit.person_attributes.natural_persons_attribute.FamilyNameAttribute;
import de.governikus.eumw.eidasstarterkit.person_attributes.natural_persons_attribute.GivenNameAttribute;
import de.governikus.eumw.eidasstarterkit.person_attributes.natural_persons_attribute.PersonIdentifierAttribute;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.xml.XMLParserException;
import se.litsec.eidas.opensaml.ext.SPTypeEnumeration;


public class EidasRoundTrip
{

  private X509KeyPair keyPair;

  private X509KeyPair keyPair2;

  private ArrayList<X509Certificate> authors;

  @Before
  public void setUp() throws InitializationException, NoSuchProviderException
  {
    EidasSaml.init();

    try
    {
      keyPair = Utils.readPKCS12(EidasRoundTrip.class.getResourceAsStream("bos-test.saml-sign.p12"),
                                 "123456".toCharArray());
      keyPair2 = Utils.readPKCS12(EidasRoundTrip.class.getResourceAsStream("bos-test.saml-sign.p12"),
                                  "123456".toCharArray());
    }
    catch (UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException | CertificateException
      | IOException e)
    {
      e.printStackTrace();
    }

    authors = new ArrayList<>();
    authors.add(keyPair.getCert());
  }

  @Test
  public void test() throws SAXException
  {
    String destination = "http://eu-middleware/receiver";
    String issuer = "http://testSP";
    EidasSigner signer = new EidasSigner(true, keyPair.getKey(), keyPair.getCert());
    Map<EidasPersonAttributes, Boolean> requestedAttributes = new HashMap<>();
    requestedAttributes.put(EidasNaturalPersonAttributes.FIRST_NAME, true);
    requestedAttributes.put(EidasNaturalPersonAttributes.FAMILY_NAME, false);
    requestedAttributes.put(EidasNaturalPersonAttributes.PERSON_IDENTIFIER, true);
    try
    {
      byte[] result = EidasSaml.createRequest(issuer,
                                              destination,
                                              signer,
                                              requestedAttributes,
                                              SPTypeEnumeration.PRIVATE,
                                              EidasNameIdType.PERSISTENT,
                                              EidasLoaEnum.LOA_LOW);


      String s = new String(result, StandardCharsets.UTF_8);
      Assert.assertTrue(s != null);
      EidasRequest eidasRequest = null;
      try (ByteArrayInputStream is = new ByteArrayInputStream(result))
      {
        EidasSaml.validateXMLRequest(is, true);
        eidasRequest = EidasSaml.parseRequest(is);

        // EidasSaml.ValidateEidasRequest(eidasRequest);
        Assert.assertTrue(Constants.DEFAULT_PROVIDER_NAME.equals(eidasRequest.getProviderName()));
        Assert.assertTrue(destination.equals(eidasRequest.getDestination()));
        Assert.assertTrue(issuer.equals(eidasRequest.getIssuer()));
        Assert.assertTrue(SPTypeEnumeration.PRIVATE == eidasRequest.getSectorType());
        Assert.assertTrue(EidasNameIdType.PERSISTENT.equals(eidasRequest.getNameIdPolicy()));
        Assert.assertTrue(EidasLoaEnum.LOA_LOW == eidasRequest.getAuthClassRef());

      }
      catch (ErrorCodeException e)
      {
        e.printStackTrace();
      }

      ArrayList<EidasAttribute> att = new ArrayList<>();
      att.add(new FamilyNameAttribute("Meyer", "Wurst"));
      att.add(new GivenNameAttribute("hans"));
      att.add(new PersonIdentifierAttribute("asdasdads"));

      try
      {
        result = EidasSaml.createResponse(att,
                                          "http://testSP/receive",
                                          "http://testSP/receive",
                                          new EidasTransientNameId("asdasdads"),
                                          "http://eu-middleware",
                                          EidasLoaEnum.LOA_LOW,
                                          "_inresp",
                                          new EidasEncrypter(true, keyPair2.getCert()),
                                          signer);
        s = new String(result, StandardCharsets.UTF_8);
        Assert.assertTrue(s != null);
        try (ByteArrayInputStream is = new ByteArrayInputStream(result))
        {
          try
          {
            EidasSaml.validateXMLRequest(is, true);
            EidasResponse eidasResponse = EidasSaml.parseResponse(is,
                                                                  new Utils.X509KeyPair[]{keyPair2},
                                                                  new X509Certificate[]{keyPair.getCert()});
            Assert.assertTrue(eidasResponse != null);

            for ( EidasAttribute atr : eidasResponse.getAttributes() )
            {
              if (atr instanceof FamilyNameAttribute)
              {
                FamilyNameAttribute fatr = (FamilyNameAttribute)atr;
                Assert.assertTrue("Meyer".equals(fatr.getValue()));
                Assert.assertTrue("Wurst".equals(fatr.getNonLatinScript()));
              }
            }
          }
          catch (ErrorCodeException e)
          {
            e.printStackTrace();
          }
        }
        System.out.println(s);
      }
      catch (NoSuchAlgorithmException | KeyException | EncryptionException e)
      {
        e.printStackTrace();
      }
    }
    catch (CertificateEncodingException | InitializationException | IOException | XMLParserException
      | UnmarshallingException | MarshallingException | SignatureException
      | TransformerFactoryConfigurationError | TransformerException | ComponentInitializationException e)
    {
      e.printStackTrace();
    }
  }
}

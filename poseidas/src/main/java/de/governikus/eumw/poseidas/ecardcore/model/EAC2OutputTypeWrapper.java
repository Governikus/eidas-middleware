/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.ecardcore.model;


import org.w3c.dom.Element;

import de.governikus.eumw.poseidas.cardbase.Hex;
import de.governikus.eumw.poseidas.ecardcore.utilities.EACElementUtil;
import iso.std.iso_iec._24727.tech.schema.EAC2OutputType;


public class EAC2OutputTypeWrapper extends EAC2OutputType
{

  private static final long serialVersionUID = 12345L;

  private static final String ELEMENT_EF_CARD_SECURITY = "EFCardSecurity";

  private static final String ELEMENT_AUTHENTICATION_TOKEN = "AuthenticationToken";

  private static final String ELEMENT_NONCE = "Nonce";

  private static final String ELEMENT_CHALLENGE = "Challenge";

  private static final String ELEMENT_EPHEMERAL_PUBLIC_KEY = "EphemeralPublicKey";


  public EAC2OutputTypeWrapper()
  {
    super();
  }

  public EAC2OutputTypeWrapper(EAC2OutputType data)
  {
    super();
    super.setProtocol(data.getProtocol());
    super.getAny().addAll(data.getAny());
    super.getOtherAttributes().putAll(data.getOtherAttributes());
  }

  public void setEFCardSecurity(byte[] ef)
  {
    for ( Element e : super.getAny() )
    {
      if (ELEMENT_EF_CARD_SECURITY.equals(e.getLocalName()))
      {
        e.setTextContent(Hex.hexify(ef));
        return;
      }
    }
    EACElementUtil.addElement(this, 0, ELEMENT_EF_CARD_SECURITY, Hex.hexify(ef));
  }

  public byte[] getEFCardSecurity()
  {
    return getUniqueElement(ELEMENT_EF_CARD_SECURITY);
  }

  public void setAuthenticationToken(byte[] token)
  {
    int index = 0;
    for ( Element e : super.getAny() )
    {
      String nodeName = e.getLocalName();
      if (ELEMENT_EF_CARD_SECURITY.equals(nodeName))
      {
        index++;
      }
      else if (ELEMENT_AUTHENTICATION_TOKEN.equals(nodeName))
      {
        e.setTextContent(Hex.hexify(token));
        return;
      }
    }
    EACElementUtil.addElement(this, index, ELEMENT_AUTHENTICATION_TOKEN, Hex.hexify(token));
  }

  public byte[] getAuthenticationToken()
  {
    return getUniqueElement(ELEMENT_AUTHENTICATION_TOKEN);
  }

  public void setNonce(byte[] nonce)
  {
    int index = 0;
    for ( Element e : super.getAny() )
    {
      String nodeName = e.getLocalName();
      if (ELEMENT_EF_CARD_SECURITY.equals(nodeName) || ELEMENT_AUTHENTICATION_TOKEN.equals(nodeName))
      {
        index++;
      }
      else if (ELEMENT_NONCE.equals(nodeName))
      {
        e.setTextContent(Hex.hexify(nonce));
        return;
      }
    }
    EACElementUtil.addElement(this, index, ELEMENT_NONCE, Hex.hexify(nonce));
  }

  public byte[] getNonce()
  {
    return getUniqueElement(ELEMENT_NONCE);
  }

  public void setChallenge(byte[] chal)
  {
    int index = 0;
    for ( Element e : super.getAny() )
    {
      String nodeName = e.getLocalName();
      if (ELEMENT_EF_CARD_SECURITY.equals(nodeName) || ELEMENT_AUTHENTICATION_TOKEN.equals(nodeName)
          || ELEMENT_NONCE.equals(nodeName))
      {
        index++;
      }
      else if (ELEMENT_CHALLENGE.equals(nodeName))
      {
        e.setTextContent(Hex.hexify(chal));
        return;
      }
    }
    EACElementUtil.addElement(this, index, ELEMENT_CHALLENGE, Hex.hexify(chal));
  }

  public byte[] getChallenge()
  {
    return getUniqueElement(ELEMENT_CHALLENGE);
  }

  public void setEphemeralPublicKey(byte[] key)
  {
    for ( Element e : super.getAny() )
    {
      if (ELEMENT_EPHEMERAL_PUBLIC_KEY.equals(e.getLocalName()))
      {
        e.setTextContent(Hex.hexify(key));
        return;
      }
    }
    EACElementUtil.addElement(this, super.getAny().size(), ELEMENT_EPHEMERAL_PUBLIC_KEY, Hex.hexify(key));
  }

  public byte[] getEphemeralPublicKey()
  {
    return getUniqueElement(ELEMENT_EPHEMERAL_PUBLIC_KEY);
  }


  private byte[] getUniqueElement(String localName)
  {
    byte[] value = null;
    for ( Element e : super.getAny() )
    {
      if (localName.equals(e.getLocalName()))
      {
        if (value != null)
        {
          throw new IllegalArgumentException("Element \"" + localName + "\" not unique");
        }
        value = Hex.parse(e.getTextContent());
      }
    }
    return value;
  }
}

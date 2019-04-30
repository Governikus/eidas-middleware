/*
 * Copyright (c) 2019 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.ecardcore.model;

import java.util.ArrayList;
import java.util.List;

import org.w3c.dom.Element;

import de.governikus.eumw.poseidas.cardbase.Hex;
import de.governikus.eumw.poseidas.ecardcore.utilities.EACElementUtil;
import iso.std.iso_iec._24727.tech.schema.EAC2InputType;


public class EAC2InputTypeWrapper extends EAC2InputType
{

  private static final long serialVersionUID = 12345L;

  private static final String ELEMENT_CERTIFICATE = "Certificate";

  private static final String ELEMENT_EPHEMERAL_PUBLIC_KEY = "EphemeralPublicKey";

  private static final String ELEMENT_SIGNATURE = "Signature";


  public EAC2InputTypeWrapper()
  {
    super();
  }

  public void setCertificateList(List<byte[]> certList)
  {
    List<Element> toRemove = new ArrayList<>();
    for ( Element e : super.getAny() )
    {
      if (ELEMENT_CERTIFICATE.equals(e.getLocalName()))
      {
        toRemove.add(e);
      }
    }
    super.getAny().removeAll(toRemove);

    for ( byte[] cert : certList )
    {
      this.addCertificate(cert);
    }
  }

  private void addCertificate(byte[] cert)
  {
    EACElementUtil.addElement(this, 0, ELEMENT_CERTIFICATE, Hex.hexify(cert));
  }

  public List<byte[]> getCertificateList()
  {
    List<byte[]> result = new ArrayList<>();
    for ( Element e : super.getAny() )
    {
      if (ELEMENT_CERTIFICATE.equals(e.getLocalName()))
      {
        result.add(Hex.parse(e.getTextContent()));
      }
    }
    return result;
  }

  public void setEphemeralPublicKey(byte[] key)
  {
    int index = 0;
    for ( Element e : super.getAny() )
    {
      String nodeName = e.getLocalName();
      if (ELEMENT_CERTIFICATE.equals(nodeName))
      {
        index++;
      }
      else if (ELEMENT_EPHEMERAL_PUBLIC_KEY.equals(nodeName))
      {
        e.setTextContent(Hex.hexify(key));
        return;
      }
    }
    EACElementUtil.addElement(this, index, ELEMENT_EPHEMERAL_PUBLIC_KEY, Hex.hexify(key));
  }

  public byte[] getEphemeralPublicKey()
  {
    for ( Element e : super.getAny() )
    {
      if (ELEMENT_EPHEMERAL_PUBLIC_KEY.equals(e.getLocalName()))
      {
        return Hex.parse(e.getTextContent());
      }
    }
    return null;
  }

  public void setSignature(byte[] sig)
  {
    for ( Element e : super.getAny() )
    {
      if (ELEMENT_SIGNATURE.equals(e.getLocalName()))
      {
        e.setTextContent(Hex.hexify(sig));
        return;
      }
    }
    EACElementUtil.addElement(this, super.getAny().size(), ELEMENT_SIGNATURE, Hex.hexify(sig));
  }

  public byte[] getSignature()
  {
    for ( Element e : super.getAny() )
    {
      if (ELEMENT_SIGNATURE.equals(e.getLocalName()))
      {
        return Hex.parse(e.getTextContent());
      }
    }
    return null;
  }
}

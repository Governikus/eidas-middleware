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


import java.util.ArrayList;
import java.util.List;

import org.w3c.dom.Element;

import de.governikus.eumw.poseidas.cardbase.Hex;
import de.governikus.eumw.poseidas.ecardcore.utilities.EACElementUtil;
import iso.std.iso_iec._24727.tech.schema.EAC1OutputType;
import iso.std.iso_iec._24727.tech.schema.ExtendedAccessPermission;


public class EAC1OutputTypeWrapper extends EAC1OutputType
{

  private static final long serialVersionUID = 12345L;

  private static final String ELEMENT_CERTIFICATE_HOLDER_AUTHORIZATION_TEMPLATE = "CertificateHolderAuthorizationTemplate";

  private static final String ELEMENT_CERTIFICATION_AUTHORITY_REFERENCE = "CertificationAuthorityReference";

  private static final String ELEMENT_EF_CARD_ACCESS = "EFCardAccess";

  private static final String ELEMENT_IDPICC = "IDPICC";

  private static final String ELEMENT_CHALLENGE = "Challenge";

  private static final String ELEMENT_GRANTED_PERMISSION = "GrantedPermission";


  public EAC1OutputTypeWrapper()
  {
    super();
  }

  public EAC1OutputTypeWrapper(EAC1OutputType data)
  {
    super();
    super.setProtocol(data.getProtocol());
    super.getAny().addAll(data.getAny());
    super.getOtherAttributes().putAll(data.getOtherAttributes());
  }

  public void setCertificateHolderAuthorizationTemplate(byte[] chat)
  {
    for ( Element e : super.getAny() )
    {
      if (ELEMENT_CERTIFICATE_HOLDER_AUTHORIZATION_TEMPLATE.equals(e.getLocalName()))
      {
        e.setTextContent(Hex.hexify(chat));
        return;
      }
    }
    EACElementUtil.addElement(this, 0, ELEMENT_CERTIFICATE_HOLDER_AUTHORIZATION_TEMPLATE, Hex.hexify(chat));
  }

  public byte[] getCertificateHolderAuthorizationTemplate()
  {
    for ( Element e : super.getAny() )
    {
      if (ELEMENT_CERTIFICATE_HOLDER_AUTHORIZATION_TEMPLATE.equals(e.getLocalName()))
      {
        return Hex.parse(e.getTextContent());
      }
    }
    return null;
  }

  public void setCertificationAuthorityReference(List<String> carList)
  {
    int index = 0;
    List<Element> toRemove = new ArrayList<>();
    for ( Element e : super.getAny() )
    {
      String nodeName = e.getLocalName();
      if (ELEMENT_CERTIFICATE_HOLDER_AUTHORIZATION_TEMPLATE.equals(nodeName))
      {
        index++;
      }
      else if (ELEMENT_CERTIFICATION_AUTHORITY_REFERENCE.equals(nodeName))
      {
        toRemove.add(e);
      }
    }
    super.getAny().removeAll(toRemove);

    for ( String car : carList )
    {
      EACElementUtil.addElement(this, index, ELEMENT_CERTIFICATION_AUTHORITY_REFERENCE, car);
    }
  }

  public List<String> getCertificationAuthorityReference()
  {
    List<String> result = new ArrayList<>();
    for ( Element e : super.getAny() )
    {
      if (ELEMENT_CERTIFICATION_AUTHORITY_REFERENCE.equals(e.getLocalName()))
      {
        result.add(e.getTextContent());
      }
    }
    return result;
  }

  public void setEFCardAccess(byte[] ef)
  {
    int index = 0;
    for ( Element e : super.getAny() )
    {
      String nodeName = e.getLocalName();
      if (ELEMENT_CERTIFICATE_HOLDER_AUTHORIZATION_TEMPLATE.equals(nodeName)
          || ELEMENT_CERTIFICATION_AUTHORITY_REFERENCE.equals(nodeName))
      {
        index++;
      }
      else if (ELEMENT_EF_CARD_ACCESS.equals(nodeName))
      {
        e.setTextContent(Hex.hexify(ef));
        return;
      }
    }
    EACElementUtil.addElement(this, index, ELEMENT_EF_CARD_ACCESS, Hex.hexify(ef));
  }

  public byte[] getEFCardAccess()
  {
    for ( Element e : super.getAny() )
    {
      if (ELEMENT_EF_CARD_ACCESS.equals(e.getLocalName()))
      {
        return Hex.parse(e.getTextContent());
      }
    }
    return null;
  }

  public void setIDPICC(byte[] id)
  {
    int index = 0;
    for ( Element e : super.getAny() )
    {
      String nodeName = e.getLocalName();
      if (ELEMENT_CERTIFICATE_HOLDER_AUTHORIZATION_TEMPLATE.equals(nodeName)
          || ELEMENT_CERTIFICATION_AUTHORITY_REFERENCE.equals(nodeName)
          || ELEMENT_EF_CARD_ACCESS.equals(nodeName))
      {
        index++;
      }
      else if (ELEMENT_IDPICC.equals(nodeName))
      {
        e.setTextContent(Hex.hexify(id));
        return;
      }
    }
    EACElementUtil.addElement(this, index, ELEMENT_IDPICC, Hex.hexify(id));
  }

  public byte[] getIDPICC()
  {
    for ( Element e : super.getAny() )
    {
      if (ELEMENT_IDPICC.equals(e.getLocalName()))
      {
        return Hex.parse(e.getTextContent());
      }
    }
    return null;
  }

  public void setChallenge(byte[] ch)
  {
    int index = 0;
    for ( Element e : super.getAny() )
    {
      String nodeName = e.getLocalName();
      if (ELEMENT_CERTIFICATE_HOLDER_AUTHORIZATION_TEMPLATE.equals(nodeName)
          || ELEMENT_CERTIFICATION_AUTHORITY_REFERENCE.equals(nodeName)
          || ELEMENT_EF_CARD_ACCESS.equals(nodeName) || ELEMENT_IDPICC.equals(nodeName))
      {
        index++;
      }
      else if (ELEMENT_CHALLENGE.equals(nodeName))
      {
        e.setTextContent(Hex.hexify(ch));
        return;
      }
    }
    EACElementUtil.addElement(this, index, ELEMENT_CHALLENGE, Hex.hexify(ch));
  }

  public byte[] getChallenge()
  {
    for ( Element e : super.getAny() )
    {
      if (ELEMENT_CHALLENGE.equals(e.getLocalName()))
      {
        return Hex.parse(e.getTextContent());
      }
    }
    return null;
  }

  public void setGrantedPermissionList(List<ExtendedAccessPermission> permList)
  {
    List<Element> toRemove = new ArrayList<>();
    for ( Element e : super.getAny() )
    {
      if (ELEMENT_GRANTED_PERMISSION.equals(e.getLocalName()))
      {
        toRemove.add(e);
      }
    }
    super.getAny().removeAll(toRemove);

    for ( ExtendedAccessPermission perm : permList )
    {
      this.addGrantedPermission(perm);
    }
  }

  private void addGrantedPermission(ExtendedAccessPermission permission)
  {
    EACElementUtil.addElement(this,
                              super.getAny().size(),
                              ELEMENT_GRANTED_PERMISSION,
                              permission.getType(),
                              Hex.hexify(permission.getValue()));
  }

  public List<ExtendedAccessPermission> getGrantedPermissionList()
  {
    List<ExtendedAccessPermission> result = new ArrayList<>();
    for ( Element e : super.getAny() )
    {
      if (ELEMENT_GRANTED_PERMISSION.equals(e.getLocalName()))
      {
        ExtendedAccessPermission eap = new ExtendedAccessPermission();
        eap.setType(e.getAttribute(EACElementUtil.ATTRIBUTE_TYPE));
        eap.setValue(Hex.parse(e.getTextContent()));
        result.add(eap);
      }
    }
    return result;
  }
}

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
import iso.std.iso_iec._24727.tech.schema.EAC1InputType;
import iso.std.iso_iec._24727.tech.schema.ExtendedAccessPermission;


public class EAC1InputTypeWrapper extends EAC1InputType
{

  private static final long serialVersionUID = 12345L;

  private static final String ELEMENT_CERTIFICATE = "Certificate";

  private static final String ELEMENT_CERTIFICATE_DESCRIPTION = "CertificateDescription";

  private static final String ELEMENT_REQUIRED_CHAT = "RequiredCHAT";

  private static final String ELEMENT_OPTIONAL_CHAT = "OptionalCHAT";

  private static final String ELEMENT_AUTHENTICATED_AUXILIARY_DATA = "AuthenticatedAuxiliaryData";

  private static final String ELEMENT_TRANSACTION_INFO = "TransactionInfo";

  private static final String ELEMENT_REQUIRED_PERMISSION = "RequiredPermission";

  private static final String ELEMENT_OPTIONAL_PERMISSION = "OptionalPermission";


  public EAC1InputTypeWrapper()
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

  public void addCertificate(byte[] cert)
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

  public void setCertificateDescription(byte[] cd)
  {
    int index = 0;
    for ( Element e : super.getAny() )
    {
      String nodeName = e.getLocalName();
      if (ELEMENT_CERTIFICATE.equals(nodeName))
      {
        index++;
      }
      else if (ELEMENT_CERTIFICATE_DESCRIPTION.equals(nodeName))
      {
        e.setTextContent(Hex.hexify(cd));
        return;
      }
    }
    EACElementUtil.addElement(this, index, ELEMENT_CERTIFICATE_DESCRIPTION, Hex.hexify(cd));
  }

  public byte[] getCertificateDescription()
  {
    for ( Element e : super.getAny() )
    {
      if (ELEMENT_CERTIFICATE_DESCRIPTION.equals(e.getLocalName()))
      {
        return Hex.parse(e.getTextContent());
      }
    }
    return null;
  }

  public void setRequiredCHAT(byte[] rChat)
  {
    int index = 0;
    for ( Element e : super.getAny() )
    {
      String nodeName = e.getLocalName();
      if (ELEMENT_CERTIFICATE.equals(nodeName) || ELEMENT_CERTIFICATE_DESCRIPTION.equals(nodeName))
      {
        index++;
      }
      else if (ELEMENT_REQUIRED_CHAT.equals(nodeName))
      {
        e.setTextContent(Hex.hexify(rChat));
        return;
      }
    }
    EACElementUtil.addElement(this, index, ELEMENT_REQUIRED_CHAT, Hex.hexify(rChat));
  }

  public byte[] getRequiredCHAT()
  {
    for ( Element e : super.getAny() )
    {
      if (ELEMENT_REQUIRED_CHAT.equals(e.getLocalName()))
      {
        return Hex.parse(e.getTextContent());
      }
    }
    return null;
  }

  public void setOptionalCHAT(byte[] oChat)
  {
    int index = 0;
    for ( Element e : super.getAny() )
    {
      String nodeName = e.getLocalName();
      if (ELEMENT_CERTIFICATE.equals(nodeName) || ELEMENT_CERTIFICATE_DESCRIPTION.equals(nodeName)
          || ELEMENT_REQUIRED_CHAT.equals(nodeName))
      {
        index++;
      }
      else if (ELEMENT_OPTIONAL_CHAT.equals(nodeName))
      {
        e.setTextContent(Hex.hexify(oChat));
        return;
      }
    }
    EACElementUtil.addElement(this, index, ELEMENT_OPTIONAL_CHAT, Hex.hexify(oChat));
  }

  public byte[] getOptionalCHAT()
  {
    for ( Element e : super.getAny() )
    {
      if (ELEMENT_OPTIONAL_CHAT.equals(e.getLocalName()))
      {
        return Hex.parse(e.getTextContent());
      }
    }
    return null;
  }

  public void setAuthenticatedAuxiliaryData(byte[] data)
  {
    int index = 0;
    for ( Element e : super.getAny() )
    {
      String nodeName = e.getLocalName();
      if (ELEMENT_CERTIFICATE.equals(nodeName) || ELEMENT_CERTIFICATE_DESCRIPTION.equals(nodeName)
          || ELEMENT_REQUIRED_CHAT.equals(nodeName) || ELEMENT_OPTIONAL_CHAT.equals(nodeName))
      {
        index++;
      }
      else if (ELEMENT_AUTHENTICATED_AUXILIARY_DATA.equals(nodeName))
      {
        e.setTextContent(Hex.hexify(data));
        return;
      }
    }
    EACElementUtil.addElement(this, index, ELEMENT_AUTHENTICATED_AUXILIARY_DATA, Hex.hexify(data));
  }

  public byte[] getAuthenticatedAuxiliaryData()
  {
    for ( Element e : super.getAny() )
    {
      if (ELEMENT_AUTHENTICATED_AUXILIARY_DATA.equals(e.getLocalName()))
      {
        return Hex.parse(e.getTextContent());
      }
    }
    return null;
  }

  public void setTransactionInfo(String ti)
  {
    int index = 0;
    for ( Element e : super.getAny() )
    {
      String nodeName = e.getLocalName();
      if (ELEMENT_CERTIFICATE.equals(nodeName) || ELEMENT_CERTIFICATE_DESCRIPTION.equals(nodeName)
          || ELEMENT_REQUIRED_CHAT.equals(nodeName) || ELEMENT_OPTIONAL_CHAT.equals(nodeName)
          || ELEMENT_AUTHENTICATED_AUXILIARY_DATA.equals(nodeName))
      {
        index++;
      }
      else if (ELEMENT_TRANSACTION_INFO.equals(e.getLocalName()))
      {
        e.setTextContent(ti);
        return;
      }
    }
    EACElementUtil.addElement(this, index, ELEMENT_TRANSACTION_INFO, ti);
  }

  public String getTransactionInfo()
  {
    for ( Element e : super.getAny() )
    {
      if (ELEMENT_TRANSACTION_INFO.equals(e.getLocalName()))
      {
        return e.getTextContent();
      }
    }
    return null;
  }

  public void setRequiredPermissionList(List<ExtendedAccessPermission> permList)
  {
    List<Element> toRemove = new ArrayList<>();
    for ( Element e : super.getAny() )
    {
      if (ELEMENT_REQUIRED_PERMISSION.equals(e.getLocalName()))
      {
        toRemove.add(e);
      }
    }
    super.getAny().removeAll(toRemove);

    for ( ExtendedAccessPermission perm : permList )
    {
      this.addRequiredPermission(perm);
    }
  }

  public void addRequiredPermission(ExtendedAccessPermission permission)
  {
    this.addPermission(permission, true);
  }

  public List<ExtendedAccessPermission> getRequiredPermissionList()
  {
    List<ExtendedAccessPermission> result = new ArrayList<>();
    for ( Element e : super.getAny() )
    {
      if (ELEMENT_REQUIRED_PERMISSION.equals(e.getLocalName()))
      {
        ExtendedAccessPermission eap = new ExtendedAccessPermission();
        eap.setType(e.getAttribute(EACElementUtil.ATTRIBUTE_TYPE));
        eap.setValue(Hex.parse(e.getTextContent()));
        result.add(eap);
      }
    }
    return result;
  }

  public void setOptionalPermissionList(List<ExtendedAccessPermission> permList)
  {
    List<Element> toRemove = new ArrayList<>();
    for ( Element e : super.getAny() )
    {
      if (ELEMENT_OPTIONAL_PERMISSION.equals(e.getLocalName()))
      {
        toRemove.add(e);
      }
    }
    super.getAny().removeAll(toRemove);

    for ( ExtendedAccessPermission perm : permList )
    {
      this.addOptionalPermission(perm);
    }
  }

  public void addOptionalPermission(ExtendedAccessPermission permission)
  {
    this.addPermission(permission, false);
  }

  public List<ExtendedAccessPermission> getOptionalPermissionList()
  {
    List<ExtendedAccessPermission> result = new ArrayList<>();
    for ( Element e : super.getAny() )
    {
      if (ELEMENT_OPTIONAL_PERMISSION.equals(e.getLocalName()))
      {
        ExtendedAccessPermission eap = new ExtendedAccessPermission();
        eap.setType(e.getAttribute(EACElementUtil.ATTRIBUTE_TYPE));
        eap.setValue(Hex.parse(e.getTextContent()));
        result.add(eap);
      }
    }
    return result;
  }

  private void addPermission(ExtendedAccessPermission permission, boolean required)
  {
    int index = 0;
    if (required)
    {
      for ( Element e : super.getAny() )
      {
        String nodeName = e.getLocalName();
        if (ELEMENT_CERTIFICATE.equals(nodeName) || ELEMENT_CERTIFICATE_DESCRIPTION.equals(nodeName)
            || ELEMENT_REQUIRED_CHAT.equals(nodeName) || ELEMENT_OPTIONAL_CHAT.equals(nodeName)
            || ELEMENT_AUTHENTICATED_AUXILIARY_DATA.equals(nodeName)
            || ELEMENT_TRANSACTION_INFO.equals(nodeName))
        {
          index++;
        }
      }
    }
    else
    {
      index = super.getAny().size();
    }
    EACElementUtil.addElement(this, index, required ? ELEMENT_REQUIRED_PERMISSION
      : ELEMENT_OPTIONAL_PERMISSION, permission.getType(), Hex.hexify(permission.getValue()));
  }
}

/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.eidasstarterkit;

/**
 * @author hohnholt
 */
public class EidasContactPerson
{

  private String company;

  private String givenName;

  private String surName;

  private String tel;

  private String email;

  private String type;

  public EidasContactPerson(String company, String givenName, String surName, String tel, String email)
  {
    this(company, givenName, surName, tel, email, null);
  }

  public EidasContactPerson(String company,
                            String givenName,
                            String surName,
                            String tel,
                            String email,
                            String type)
  {
    super();
    this.company = company;
    this.givenName = givenName;
    this.surName = surName;
    this.tel = tel;
    this.email = email;
    this.type = type;
  }

  public String getCompany()
  {
    return company;
  }

  public void setCompany(String company)
  {
    this.company = company;
  }

  public String getGivenName()
  {
    return givenName;
  }

  public void setGivenName(String givenName)
  {
    this.givenName = givenName;
  }

  public String getSurName()
  {
    return surName;
  }

  public void setSurName(String surName)
  {
    this.surName = surName;
  }

  public String getTel()
  {
    return tel;
  }

  public void setTel(String tel)
  {
    this.tel = tel;
  }

  public String getEmail()
  {
    return email;
  }

  public void setEmail(String email)
  {
    this.email = email;
  }

  public String getType()
  {
    return type;
  }

  public void setType(String type)
  {
    this.type = type;
  }
}

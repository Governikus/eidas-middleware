/*
 * Copyright (c) 2021 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.eidasmiddleware.mapper;

import de.governikus.eumw.config.ContactType;
import de.governikus.eumw.config.OrganizationType;
import de.governikus.eumw.eidasstarterkit.EidasContactPerson;
import de.governikus.eumw.eidasstarterkit.EidasOrganisation;
import lombok.experimental.UtilityClass;


/**
 * Map between {@link EidasOrganisation} from the eIDAS SAML package and {@link EidasContactPerson} from the
 * configuration.
 */
@UtilityClass
public class EidasMapper
{

  public static EidasOrganisation toEidasOrganisation(OrganizationType organizationType)
  {
    return new EidasOrganisation(organizationType.getName(), organizationType.getDisplayname(),
                                 organizationType.getUrl(), organizationType.getLanguage());
  }

  public static EidasContactPerson toEidasContactPerson(ContactType contactType)
  {
    return new EidasContactPerson(contactType.getCompany(), contactType.getGivenname(), contactType.getSurname(),
                                  contactType.getTelephone(), contactType.getEmail());
  }
}

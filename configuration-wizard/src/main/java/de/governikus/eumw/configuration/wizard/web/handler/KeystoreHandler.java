/*
 * Copyright (c) 2019 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.configuration.wizard.web.handler;

import org.springframework.stereotype.Service;

import de.governikus.eumw.configuration.wizard.web.model.KeystoreForm;


/**
 * project: eumw <br>
 * author Pascal Knueppel <br>
 * created at: 12.02.2018 - 08:06 <br>
 * <br>
 * this service is used as a storage repository for uploaded keystore files
 */
@Service
public class KeystoreHandler extends ViewObjectHandler<KeystoreForm>
{}

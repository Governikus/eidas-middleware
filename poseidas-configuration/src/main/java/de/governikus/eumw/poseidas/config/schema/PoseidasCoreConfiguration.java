/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.config.schema;

import javax.xml.bind.annotation.XmlRootElement;


/**
 * project: eumw <br>
 * 
 * @author Pascal Knueppel <br>
 *         created at: 09.02.2018 - 12:55 <br>
 *         <br>
 *         empty wrapper class for the poseidas core configuration to work around problems with annotation
 *         jaxb:bindings with the already existing code. <br>
 *         If code generation is done with binding &lt;xjc:simple /> the class structures as well as the
 *         method names will change in an inconvenient way to the already existing code. Therefore we will use
 *         this wrapper class for adding {@link XmlRootElement}
 */
@XmlRootElement(name = "CoreConfiguration")
public class PoseidasCoreConfiguration extends CoreConfigurationType
{}

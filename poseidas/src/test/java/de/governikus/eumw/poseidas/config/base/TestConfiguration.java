/*
 * Copyright (c) 2022 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.config.base;

import java.util.Properties;

import org.apache.commons.lang3.ArrayUtils;
import org.springframework.boot.info.BuildProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import de.governikus.eumw.poseidas.service.MetadataService;


@Configuration
public class TestConfiguration
{

  @Bean
  MetadataService metadataService()
  {

    return () -> ArrayUtils.EMPTY_BYTE_ARRAY;
  }

  @Bean
  BuildProperties buildProperties()
  {

    Properties entries = new Properties();
    entries.put("version", "TEST");
    return new BuildProperties(entries);
  }

}

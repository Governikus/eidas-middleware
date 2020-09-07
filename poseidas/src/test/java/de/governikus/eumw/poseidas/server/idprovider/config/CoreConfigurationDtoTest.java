/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.idprovider.config;

import java.io.InputStream;
import java.io.Reader;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.google.common.io.ByteStreams;
import com.google.common.io.CharSource;

import de.governikus.eumw.poseidas.server.idprovider.exceptions.InvalidConfigurationException;


class CoreConfigurationDtoTest
{

  @Test
  void validateConfigThrowsExceptionWhenDuplicatedEntityPresent() throws Exception
  {
    InputStream resourceAsStream = CoreConfigurationDtoTest.class.getResourceAsStream("/POSeIDAS-duplicated-SP.xml");
    byte[] bytes = ByteStreams.toByteArray(resourceAsStream);
    Reader reader = CharSource.wrap(new String(bytes)).openStream();

    Assertions.assertThrows(InvalidConfigurationException.class, () -> CoreConfigurationDto.readFrom(reader));
  }
}

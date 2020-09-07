/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardbase.constants;

import de.governikus.eumw.poseidas.cardbase.Hex;
import de.governikus.eumw.poseidas.cardbase.ImmutableByteArray;


public final class ESignConstants
{

  public static final ImmutableByteArray AID_ESIGN = ImmutableByteArray.of(Hex.parse("a000000167455349474e"));

  public static final ImmutableByteArray AID_CIA_ESIGN = ImmutableByteArray.of(Hex.parse("e828bd080fa000000167455349474e"));

  public static final ImmutableByteArray EF_OD = ImmutableByteArray.of(Hex.parse("5031"));

  public static final int RW_BLOCK_SIZE = 0x200;

  private ESignConstants()
  {}

}

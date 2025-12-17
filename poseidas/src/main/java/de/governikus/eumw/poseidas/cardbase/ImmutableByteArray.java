/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardbase;

import java.util.Arrays;


/**
 * An immutable array of {@code Byte} values.
 */
public final class ImmutableByteArray
{

  private final byte[] bytes;

  /** Returns an immutable array containing the given values, in order. */
  public static ImmutableByteArray of(final byte[] bytes)
  {
    if (bytes == null)
    {
      return null;
    }
    else
    {
      return new ImmutableByteArray(bytes);
    }
  }

  private ImmutableByteArray(final byte[] src)
  {
    bytes = Arrays.copyOfRange(src, 0, src.length);
  }

  /** Returns a new, mutable copy of this array's values, as a primitive {@code byte[]}. */
  public byte[] toArray()
  {
    return Arrays.copyOfRange(bytes, 0, bytes.length);
  }

}

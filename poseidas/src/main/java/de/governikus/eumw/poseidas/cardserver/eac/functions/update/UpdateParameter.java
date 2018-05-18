/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardserver.eac.functions.update;

import de.governikus.eumw.poseidas.cardbase.AssertUtil;
import de.governikus.eumw.poseidas.cardserver.eac.functions.FunctionParameter;


/**
 * Parameter for updating files.
 * 
 * @author Arne Stahlbock, arne.stahlbock@governikus.com
 */
public class UpdateParameter implements FunctionParameter
{

  /**
   * Data to write.
   */
  private final byte[] data;

  /**
   * Offset in file.
   */
  private final int offset;

  /**
   * Short file identifier.
   */
  private final Byte sfi;

  /**
   * Constructor.
   * 
   * @param data data to write
   */
  public UpdateParameter(byte[] data)
  {
    this(null, data, 0);
  }

  /**
   * Constructor.
   * 
   * @param data data to write
   * @param offset offset at which to write
   */
  public UpdateParameter(byte[] data, int offset)
  {
    this(null, data, offset);
  }

  /**
   * Constructor.
   * 
   * @param sfi short file identifier
   * @param data data to write
   * @param offset offset at which to write
   */
  private UpdateParameter(Byte sfi, byte[] data, int offset)
  {
    super();
    AssertUtil.notNull(data, "data to write");
    if (data.length > 65536)
    {
      throw new IllegalArgumentException("only data length upto 65536 permitted");
    }
    if (offset < 0)
    {
      throw new IllegalArgumentException("only positive offset permitted");
    }
    if (sfi == null && offset > 32767)
    {
      throw new IllegalArgumentException("only offset upto 32767 permitted");
    }
    if (sfi != null && offset > 255)
    {
      throw new IllegalArgumentException("only offset upto 255 permitted (SFI set)");
    }

    this.sfi = sfi;
    this.data = data;
    this.offset = offset;
  }

  /**
   * Get data.
   * 
   * @return data
   */
  public byte[] getData()
  {
    return this.data;
  }

  /**
   * Get offset.
   * 
   * @return offset
   */
  public int getOffset()
  {
    return this.offset;
  }

  /**
   * Get short file identifier.
   * 
   * @return sfi
   */
  public Byte getSfi()
  {
    return this.sfi;
  }
}

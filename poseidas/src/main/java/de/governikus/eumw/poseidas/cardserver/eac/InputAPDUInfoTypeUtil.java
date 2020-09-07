/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardserver.eac;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import de.governikus.eumw.poseidas.cardbase.AssertUtil;
import de.governikus.eumw.poseidas.cardbase.CollectionUtil;
import de.governikus.eumw.poseidas.cardbase.Hex;
import iso.std.iso_iec._24727.tech.schema.InputAPDUInfoType;
import iso.std.iso_iec._24727.tech.schema.ObjectFactory;


/**
 * Utility class to handle {@link InputAPDUInfoType}.
 *
 * @author Arne Stahlbock, ast@bos-bremen.de
 * @author Jens Wothe, jw@bos-bremen.de
 */
public class InputAPDUInfoTypeUtil
{

  /**
   * Constant list with only one accepted response code: <code>9000</code>.
   */
  public static final List<byte[]> RESPONSE_CODE_ACCEPT_OK_ONLY_BYTES_LIST = Collections.unmodifiableList(Arrays.asList(Hex.parse("9000")));

  /**
   * Constructor.
   */
  private InputAPDUInfoTypeUtil()
  {
    super();
  }

  /**
   * Creates list of InputAPDUInfoType from list of commands.
   *
   * @param commandList list of commands, <code>null</code> or empty permitted, <code>null</code> entries
   *          ignored
   * @return list of InputAPDUInfoType
   */
  public static List<InputAPDUInfoType> create(List<CommandAPDU> commandList)
  {
    return create(commandList, null);
  }

  /**
   * Creates list of InputAPDUInfoType for command and optional accepted response list.
   *
   * @param commandList command, <code>null</code> ignored
   * @param acceptedResponseList optional accepted response code list, <code>null</code> for all
   * @return list of InputAPDUInfoType
   */
  public static List<InputAPDUInfoType> create(CommandAPDU command, List<ResponseAPDU> acceptedResponseList)
  {
    List<InputAPDUInfoType> result = new ArrayList<>();
    if (command != null)
    {
      result.add(createSingle(command, acceptedResponseList));
    }
    return result;
  }

  /**
   * Creates list of InputAPDUInfoType for command and optional accepted response list.
   *
   * @param commandList list of commands, <code>null</code> or empty permitted, <code>null</code> entries
   *          ignored
   * @param acceptedResponseList optional accepted response code list, <code>null</code> for all
   * @return list of InputAPDUInfoType
   */
  private static List<InputAPDUInfoType> create(List<CommandAPDU> commandList,
                                               List<ResponseAPDU> acceptedResponseList)
  {
    List<InputAPDUInfoType> result = new ArrayList<>();
    if (!CollectionUtil.isNullOrEmpty(commandList))
    {
      for ( CommandAPDU command : commandList )
      {
        if (command != null)
        {
          result.add(createSingle(command, acceptedResponseList));
        }
      }
    }
    return result;
  }

  /**
   * Creates single {@link InputAPDUInfoType}.
   *
   * @param command command, <code>null</code> not permitted
   * @param acceptedResponseList, <code>null</code> or empty ignored, <code>null</code> entries ignored
   * @return single {@link InputAPDUInfoType}
   * @throws IllegalArgumentException if command <code>null</code>
   */
  private static InputAPDUInfoType createSingle(CommandAPDU command, List<ResponseAPDU> acceptedResponseList)
  {
    AssertUtil.notNull(command, "command");
    InputAPDUInfoType iait = new ObjectFactory().createInputAPDUInfoType();
    iait.setInputAPDU(command.getBytes());
    if (acceptedResponseList != null)
    {
      for ( ResponseAPDU r : acceptedResponseList )
      {
        if (r != null)
        {
          iait.getAcceptableStatusCode().add(new byte[]{(byte)r.getSW1(), (byte)r.getSW2()});
        }
      }
    }
    return iait;
  }
}

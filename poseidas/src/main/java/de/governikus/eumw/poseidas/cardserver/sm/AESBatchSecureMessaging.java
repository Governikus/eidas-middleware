/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardserver.sm;

import java.util.ArrayList;
import java.util.List;

import javax.crypto.spec.IvParameterSpec;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import de.governikus.eumw.poseidas.cardbase.crypto.sm.AESEncSSCIvParameterSpec;
import de.governikus.eumw.poseidas.cardbase.crypto.sm.AESKeyMaterial;
import de.governikus.eumw.poseidas.cardbase.crypto.sm.AESSecureMessaging;


public class AESBatchSecureMessaging extends AESSecureMessaging implements BatchSecureMessaging
{

  /**
   * Constructor.
   *
   * @param keyMaterial key material, <code>null</code> not permitted
   * @throws IllegalArgumentException if keyMaterial <code>null</code>
   */
  public AESBatchSecureMessaging(AESKeyMaterial keyMaterial)
  {
    super(keyMaterial);
  }

  /** {@inheritDoc} */
  @Override
  public void toCard(CardCommunication cardCommunication)
  {
    Exception throwable = null;
    // encrypt commands
    List<CommandAPDU> encryptedCommandList = new ArrayList<>();

    BatchAESEncSSCIvParameterSpec paramSpec;
    IvParameterSpec iv = super.material.getIvParameterSpec();
    if (BatchAESEncSSCIvParameterSpec.class.isInstance(iv))
    {
      paramSpec = (BatchAESEncSSCIvParameterSpec)iv;
    }
    else
    {
      return;
    }

    CommandAPDU[] commands = cardCommunication.getPlaintextCommands();
    for ( int i = 0 ; i < commands.length ; i++ )
    {
      CommandAPDU command = commands[i];
      try
      {
        encryptedCommandList.add(super.encipherCommand(command));
        if (i == 0)
        {
          paramSpec.mark();
        }
        if (i != commands.length - 1)
        {
          paramSpec.increaseSSC();
        }
        else
        {
          paramSpec.reset();
        }
      }
      catch (Exception e)
      {
        throwable = e;
        break;
      }
    }
    if (throwable != null)
    {
      cardCommunication.setThrowable(throwable);
    }
    else
    {
      cardCommunication.setEncryptedCommands(encryptedCommandList.toArray(new CommandAPDU[0]));
    }
  }

  /** {@inheritDoc} */
  @Override
  public void fromCard(CardCommunication cardCommunication)
  {
    Exception throwable = null;

    AESEncSSCIvParameterSpec paramSpec;
    IvParameterSpec iv = super.material.getIvParameterSpec();
    if (AESEncSSCIvParameterSpec.class.isInstance(iv))
    {
      paramSpec = (AESEncSSCIvParameterSpec)iv;
    }
    else
    {
      return;
    }

    // decrypt response
    ResponseAPDU[] encryptedResponses = cardCommunication.getEncryptedResponses();
    List<ResponseAPDU> decryptedResponses = new ArrayList<>();
    if (encryptedResponses != null)
    {
      for ( int i = 0 ; i < encryptedResponses.length ; i++ )
      {
        ResponseAPDU response = encryptedResponses[i];
        try
        {
          ResponseAPDU decryptedResponse = super.decipherResponse(response);
          decryptedResponses.add(decryptedResponse);
          if (i != encryptedResponses.length - 1)
          {
            paramSpec.increaseSSC();
          }
        }
        catch (Exception e)
        {
          throwable = e;
          break;
        }
      }
    }
    if (throwable != null)
    {
      cardCommunication.setThrowable(throwable);
    }
    else
    {
      cardCommunication.setPlaintextResponses(decryptedResponses.toArray(new ResponseAPDU[0]));
    }
  }
}

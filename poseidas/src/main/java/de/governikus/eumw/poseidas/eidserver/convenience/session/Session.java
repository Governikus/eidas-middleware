/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.eidserver.convenience.session;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import de.governikus.eumw.poseidas.eidmodel.TerminalData;
import de.governikus.eumw.poseidas.eidserver.convenience.ChatOptionNotAllowedException;
import de.governikus.eumw.poseidas.eidserver.convenience.EIDSequence;
import de.governikus.eumw.poseidas.eidserver.ecardid.SessionInput;


/**
 * Session containing required informations to handle a successful authentication between client and server:
 * <ul>
 * <li>CVC</li>
 * <li>Required and optional CHAT</li>
 * <li>Session identifier and pre-shared key</li>
 * </ul>
 *
 * @author Alexander Funk
 * @author Edgar Thiel
 * @author Steffen Peil
 * @author Ole Behrens
 * @author <a href="mail:hme@bos-bremen.de">Hauke Mehrtens</a>
 */
public class Session implements Serializable
{

  /**
   * Serialization identifier
   */
  private static final long serialVersionUID = 4313456569705212432L;

  /**
   * Logger for debug informations
   */
  private static final Log LOG = LogFactory.getLog(Session.class.getName());

  /**
   * Leading input for this session created on server side
   */
  private final SessionInput sessionInput;

  /**
   * Class handling the authentication
   */
  private transient EIDSequence eIDSequence;

  /**
   * Session is valid until this field is expired
   */
  private final long validTo;

  /**
   * Time after which a session may be deleted if there are too many open sessions.
   */
  private static final long SESSION_TIMEOUT = 15L * 60 * 1000;


  /**
   * @param sessionInput Data provided by the EIDServer about the Session to be handled
   * @throws ChatOptionNotAllowedException if required or optional field is not allowed to be active
   * @throws IllegalArgumentException if the SessionInput contains invalid or missing data
   */
  Session(SessionInput sessionInput) throws ChatOptionNotAllowedException
  {
    if (sessionInput == null)
    {
      throw new IllegalArgumentException("Session input is null");
    }
    this.sessionInput = sessionInput;
    if (sessionInput.getSessionID() == null)
    {
      throw new IllegalArgumentException(sessionInput.getLogPrefix() + "SessionID is null."
                                         + " Session identifier must be set in session input");
    }
    if (sessionInput.getRequiredFields() == null)
    {
      throw new IllegalArgumentException(sessionInput.getLogPrefix() + "RequiredFields is null."
                                         + " Required fields must be set in session input");
    }
    if (sessionInput.getOptionalFields() == null)
    {
      throw new IllegalArgumentException(sessionInput.getLogPrefix() + "OptionalFields is null."
                                         + " Optional fields must be set in session input");
    }
    if (sessionInput.getTerminalCertificate() == null)
    {
      throw new IllegalArgumentException(sessionInput.getLogPrefix() + "TerminalCertificate is null."
                                         + " TerminalCertificate must be set in session input");
    }
    if (sessionInput.getDefectList() == null)
    {
      throw new IllegalArgumentException(sessionInput.getLogPrefix()
                                         + "DefectList is null. DefectList must be set in session input");
    }
    if (sessionInput.getMasterList() == null
        && (sessionInput.getMasterListCerts() == null || sessionInput.getMasterListCerts().isEmpty()))
    {
      throw new IllegalArgumentException(sessionInput.getLogPrefix()
                                         + "MasterList is null. MasterList must be set in session input");
    }
    List<TerminalData> cvcList = formatCVCList(sessionInput.getTerminalCertificate(),
                                               sessionInput.getCvcChain());
    if (cvcList.isEmpty())
    {
      throw new IllegalArgumentException(sessionInput.getLogPrefix() + "CVC list is empty."
                                         + " At least one CVC must be set in the session input");
    }
    int listSize = cvcList.size();
    if (listSize == 1)
    {
      LOG.debug(sessionInput.getLogPrefix() + "CVC list contains only the CVC with no DV certificate");
    }

    LOG.debug(sessionInput.getLogPrefix() + "Session input set for session");

    eIDSequence = createSequence(sessionInput.getTerminalCertificate(), cvcList, sessionInput);

    LOG.debug(sessionInput.getLogPrefix() + "EID sequence instanciated for session");
    // for every session terminal CVC is needed in the CakProvider.
    try
    {
      LOG.debug(sessionInput.getLogPrefix() + "Set a terminal CVC by session and not by manager");
      EIDSequence.getCakProvider().addTerminalCVC(sessionInput.getTerminalCertificate());
      LOG.debug(sessionInput.getLogPrefix() + "Terminal CVC added to provider for session");
      for ( TerminalData cvc : cvcList )
      {
        LOG.debug(sessionInput.getLogPrefix() + "Set a CVC by session and not by manager");
        EIDSequence.getCakProvider().addCert(cvc.getEncoded());
        LOG.debug(sessionInput.getLogPrefix() + "DV or link certificate added to provider for session");
      }
    }
    catch (IOException e)
    {
      throw new IllegalArgumentException(sessionInput.getLogPrefix()
                                         + "CVC in SessionInput is not wellformed. "
                                         + "Terminal CVC not added: ", e);
    }

    validTo = System.currentTimeMillis() + SESSION_TIMEOUT;
    LOG.debug(sessionInput.getLogPrefix() + "Session timout set to: " + validTo);
  }

  /**
   * poseidas server sets an unsorted list also with root certificates. Until this is fixed this check is
   * implemented
   *
   * @param terminalCertificate the terminal certificate to build the chain for
   * @param cvcChain the unsorted chain certificates
   * @throws IllegalArgumentException if something illegal with the input
   * @return List with the chain certificates without the terminal and the root certificate
   */
  private List<TerminalData> formatCVCList(TerminalData terminalCertificate, List<TerminalData> cvcChain)
  {
    if (cvcChain == null || terminalCertificate == null || cvcChain.isEmpty())
    {
      throw new IllegalArgumentException(sessionInput.getLogPrefix()
                                         + "Session input requires at last one CVC file: DV certificate");
    }
    if (LOG.isDebugEnabled())
    {
      LOG.debug(sessionInput.getLogPrefix() + "RECEIVED " + getCVCListOutput(cvcChain));
      LOG.debug(sessionInput.getLogPrefix() + "Parse session input CVC list with size: " + cvcChain.size());
    }
    List<TerminalData> formattedChain = new ArrayList<>();

    // Check the terminal CVC and add it to the list as first element
    if (isSelfSigned(terminalCertificate))
    {
      throw new IllegalArgumentException(sessionInput.getLogPrefix()
                                         + "First CVC in list is self signed and not the terminal CVC");
    }
    TerminalData check = terminalCertificate;
    while (true)
    {
      if (LOG.isDebugEnabled())
      {
        LOG.debug(sessionInput.getLogPrefix() + "Check CVC: " + check.getHolderReferenceString() + "/"
                  + check.getCAReferenceString());
      }
      TerminalData holder = getReference(check, cvcChain);
      if (holder == null || isSelfSigned(holder))
      {
        break;
      }
      formattedChain.add(holder);
      check = holder;
    }
    if (LOG.isDebugEnabled())
    {
      LOG.debug(sessionInput.getLogPrefix() + "SORT " + getCVCListOutput(formattedChain));
      LOG.debug(sessionInput.getLogPrefix() + "Parsed session input and set new list with size: "
                + formattedChain.size());
    }
    return formattedChain;
  }

  /**
   * Get a helper output to check the sorting
   *
   * @param list to be checked
   * @return string with all elements form list
   */
  private String getCVCListOutput(List<TerminalData> list)
  {
    StringBuilder output = new StringBuilder("OUTPUT LIST:");
    for ( TerminalData cvc : list )
    {
      if (cvc != null)
      {
        output.append("\n" + " o '" + cvc.getHolderReferenceString() + "' signed by '"
                      + cvc.getCAReferenceString() + "'");
      }
    }
    return output.toString();
  }


  /**
   * Get the signing reference from this CVC
   *
   * @param cvc to be checked
   * @param cvcList with all possible signers
   * @return an signing CVC if existing for this CVC else null
   */
  private TerminalData getReference(TerminalData cvc, List<TerminalData> cvcList)
  {
    for ( TerminalData linkCVC : cvcList )
    {
      if (Arrays.equals(cvc.getCAReference(), linkCVC.getHolderReference()))
      {
        return linkCVC;
      }
    }
    return null;
  }

  /**
   * Indicates if the given CVC is self signed
   *
   * @param cvc to be checked
   * @return true if is self signed
   */
  private boolean isSelfSigned(TerminalData cvc)
  {
    return Arrays.equals(cvc.getHolderReference(), cvc.getCAReference());
  }

  private static EIDSequence createSequence(TerminalData cvc,
                                            List<TerminalData> cvcList,
                                            SessionInput sessionInput)
    throws ChatOptionNotAllowedException
  {
    return new EIDSequence(cvc, cvcList, sessionInput);
  }

  /**
   * Get the EID sequence from session
   *
   * @return sequence instance
   */
  public EIDSequence getEIDSequence()
  {
    return eIDSequence;
  }

  /**
   * Return the time after which this session return true if session has expired. Feature is needed to avoid
   * memory leak
   *
   * @return the point in time when session is expired
   */
  public long getValidTo()
  {
    return validTo;
  }

  /**
   * Internal call to be able to get the input from a session
   *
   * @return session input
   */
  SessionInput getSessionInput()
  {
    return sessionInput;
  }

  /**
   * After session is read, session input is restored from inner implementation
   *
   * @param is for this session
   */
  private void readObject(ObjectInputStream is) throws IOException, ClassNotFoundException
  {
    is.defaultReadObject();
    try
    {
      List<TerminalData> cvcList = formatCVCList(sessionInput.getTerminalCertificate(),
                                                 sessionInput.getCvcChain());
      eIDSequence = createSequence(sessionInput.getTerminalCertificate(), cvcList, sessionInput);
    }
    catch (ChatOptionNotAllowedException e)
    {
      LOG.error(sessionInput.getLogPrefix() + "Failed to serialize session: " + e, e);
    }
  }

  @Override
  public String toString()
  {
    StringBuilder stringBuilder = new StringBuilder();
    stringBuilder.append("EID Session for identifier  =  " + sessionInput.getSessionID() + ", ");
    stringBuilder.append("session is valid to =  " + getValidTo());

    return stringBuilder.toString();

  }
}

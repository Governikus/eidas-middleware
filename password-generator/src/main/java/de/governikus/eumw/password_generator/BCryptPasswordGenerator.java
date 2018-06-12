/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.password_generator;

import org.springframework.security.crypto.bcrypt.BCrypt;

import lombok.extern.slf4j.Slf4j;


/**
 * Command line tool to create a BCrypt encrypted password <br>
 * Pass your password as an argument to this class. It must not contain whitespaces. The hashed password is
 * printed to the command line.
 *
 * @author bpr
 */
@Slf4j
public class BCryptPasswordGenerator
{

  // Generate password
  public static void main(String[] args)
  {
    if (args.length != 1 || containsHelp(args[0]))
    {
      printUsage();
      return;
    }
    String pwHash = BCrypt.hashpw(args[0], BCrypt.gensalt());
    log.info(pwHash);
  }

  private static boolean containsHelp(String string)
  {
    boolean containsHelp;
    containsHelp = "--help".equals(string) || "-h".equals(string);
    return containsHelp;
  }

  private static void printUsage()
  {
    log.info(new StringBuilder("=====================================\n").append("Usage of this program:\n")
                                                                         .append("java -jar password-generator -h for this help\n")
                                                                         .append("java -jar password-generator --help for this help\n")
                                                                         .append("java -jar password-generator [your password here]\n")
                                                                         .append("=====================================")
                                                                         .toString());
  }
}

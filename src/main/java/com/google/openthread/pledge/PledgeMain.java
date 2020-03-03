/*
 *    Copyright (c) 2019, The OpenThread Registrar Authors.
 *    All rights reserved.
 *
 *    Redistribution and use in source and binary forms, with or without
 *    modification, are permitted provided that the following conditions are met:
 *    1. Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *    2. Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *    3. Neither the name of the copyright holder nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 *    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *    AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *    IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *    ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 *    LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *    CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *    INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *    CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *    ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *    POSSIBILITY OF SUCH DAMAGE.
 */

package com.google.openthread.pledge;

import com.google.openthread.Credentials;
import com.google.openthread.commissioner.Commissioner;
import com.google.openthread.tools.CredentialGenerator;
import java.security.KeyStoreException;
import java.util.Scanner;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;

public class PledgeMain {

  private PledgeMain() {}

  public static void main(String args[]) {
    final String HELP_FORMAT = "registrar [-h] -f <keystore-file> -r <registrar-uri>";

    HelpFormatter helper = new HelpFormatter();
    Options options = new Options();

    Option fileOpt =
        Option.builder("f")
            .longOpt("file")
            .hasArg()
            .argName("keystore-file")
            .desc("the keystore file in PKCS#12 format")
            .build();

    Option optRegistrar =
        Option.builder("r")
            .longOpt("registrar")
            .hasArg()
            .argName("registrar-uri")
            .desc("the registrar connecting to")
            .build();

    Option helpOpt =
        Option.builder("h").longOpt("help").hasArg(false).desc("print this message").build();

    options.addOption(fileOpt).addOption(optRegistrar).addOption(helpOpt);

    try {
      CommandLineParser parser = new DefaultParser();
      CommandLine cmd = parser.parse(options, args);

      if (cmd.hasOption('h')) {
        helper.printHelp(HELP_FORMAT, options);
        return;
      }

      String keyStoreFile = cmd.getOptionValue('f');
      if (keyStoreFile == null) {
        throw new IllegalArgumentException("need keystore file!");
      }

      String registrarUri = cmd.getOptionValue('r');
      if (registrarUri == null) {
        throw new IllegalArgumentException("need to specify registrar!");
      }

      System.out.println("using keystore: " + keyStoreFile);

      String password = CredentialGenerator.PASSWORD;
      Credentials cred = new Credentials(keyStoreFile, CredentialGenerator.PLEDGE_ALIAS, password);

      if (cred == null || cred.getPrivateKey() == null || cred.getCertificateChain() == null) {
        throw new KeyStoreException(
            String.format(
                "can't find pledge key or certificate: %s", CredentialGenerator.PLEDGE_ALIAS));
      }

      Pledge pledge = new Pledge(cred.getPrivateKey(), cred.getCertificateChain(), registrarUri);

      cred =
          new Credentials(
              keyStoreFile, CredentialGenerator.COMMISSIONER_ALIAS, CredentialGenerator.PASSWORD);

      Commissioner commissioner = null;
      if (cred != null && cred.getPrivateKey() != null && cred.getCertificateChain() != null) {
        commissioner = new Commissioner(cred.getPrivateKey(), cred.getCertificateChain());
      } else {
        String msg = "can't find commissioner key or certificate";
        msg += ": expect alias=" + CredentialGenerator.COMMISSIONER_ALIAS;
        msg += ", password=" + CredentialGenerator.PASSWORD;
        msg += "; commissioner disabled";
        System.err.println(msg);
      }

      run(pledge, commissioner);

      if (commissioner != null) {
        commissioner.shutdown();
      }
      pledge.shutdown();
    } catch (IllegalArgumentException e) {
      System.err.println("error: " + e.getMessage());
      helper.printHelp(HELP_FORMAT, options);
    } catch (Exception e) {
      System.err.println("error: " + e.getMessage());
      return;
    }
  }

  private static void run(Pledge pledge, Commissioner commissioner) {
    final String DOMAIN_NAME = "TestDomainTCE";
    final String help =
        "token    -  request commissioning token\n"
            + "rv       -  request voucher\n"
            + "attrs    -  request CSR attributes\n"
            + "enroll   -  simple enrollment\n"
            + "reenroll -  simple reenrollment\n"
            + "reset    -  reset to initial state\n"
            + "exit     -  exit pledge CLI\n"
            + "help     -  print this help message\n";

    try (Scanner scanner = new Scanner(System.in)) {
      while (true) {
        try {
          System.out.print("> ");
          switch (scanner.nextLine().trim()) {
            case "token":
              if (commissioner != null) {
                commissioner.requestToken(DOMAIN_NAME, pledge.getHostURI());
              } else {
                throw new Exception("invalid commissioner");
              }
              break;
            case "rv":
              pledge.requestVoucher();
              break;
            case "attrs":
              pledge.requestCSRAttributes();
              break;
            case "enroll":
              pledge.enroll();
              break;
            case "reenroll":
              pledge.reenroll();
              break;
            case "reset":
              pledge.reset();
              break;
            case "exit":
              return;
            case "help":
              System.out.println(help);
              break;
            default:
              System.out.println(help);
          }

          System.out.println("done");
        } catch (Exception e) {
          e.printStackTrace();
        }
      }
    }
  }
}

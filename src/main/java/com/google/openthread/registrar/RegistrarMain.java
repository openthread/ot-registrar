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

package com.google.openthread.registrar;

import com.google.openthread.Credentials;
import com.google.openthread.LoggerInitializer;
import com.google.openthread.domainca.DomainCA;
import com.google.openthread.tools.CredentialGenerator;
import java.security.KeyStoreException;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;

public final class RegistrarMain {

  private RegistrarMain() {}

  public static void main(String args[]) {

    final String HELP_FORMAT = "registrar [-h] [-v] -d <domain-name> -f <keystore-file> -p <port>";

    HelpFormatter helper = new HelpFormatter();
    Options options = new Options();

    Option domainNameOpt =
        Option.builder("d")
            .longOpt("domainname")
            .hasArg()
            .argName("domain-name")
            .desc("the domain name")
            .build();

    Option fileOpt =
        Option.builder("f")
            .longOpt("file")
            .hasArg()
            .argName("keystore-file")
            .desc("the keystore file in PKCS#12 format")
            .build();

    Option optPort =
        Option.builder("p")
            .longOpt("port")
            .hasArg()
            .argName("port")
            .desc("the port to listen on")
            .build();

    Option optVerbose =
        Option.builder("v")
            .longOpt("verbose")
            .hasArg(false)
            .desc("verbose mode with many logs")
            .build();

    Option helpOpt =
        Option.builder("h").longOpt("help").hasArg(false).desc("print this message").build();

    options
        .addOption(domainNameOpt)
        .addOption(fileOpt)
        .addOption(optPort)
        .addOption(optVerbose)
        .addOption(helpOpt);

    Registrar registrar;

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

      String port = cmd.getOptionValue('p');
      if (port == null) {
        throw new IllegalArgumentException("need port!");
      }

      String domainName = cmd.getOptionValue('d');
      if (domainName == null) {
        throw new IllegalArgumentException("need domain name!");
      }

      LoggerInitializer.Init(cmd.hasOption('v'));

      System.out.println("using keystore: " + keyStoreFile);

      RegistrarBuilder builder = new RegistrarBuilder();
      Credentials cred =
          new Credentials(
              keyStoreFile, CredentialGenerator.REGISTRAR_ALIAS, CredentialGenerator.PASSWORD);
      Credentials domainCred =
          new Credentials(
              keyStoreFile, CredentialGenerator.DOMAINCA_ALIAS, CredentialGenerator.PASSWORD);
      Credentials masaCred =
          new Credentials(
              keyStoreFile, CredentialGenerator.MASA_ALIAS, CredentialGenerator.PASSWORD);

      if (cred.getPrivateKey() == null || cred.getCertificateChain() == null) {
        throw new KeyStoreException("can't find registrar key or certificate");
      }

      builder.setPrivateKey(cred.getPrivateKey()).setCertificateChain(cred.getCertificateChain());
      if (masaCred.getCertificate() != null) {
        builder.addMasaCertificate(masaCred.getCertificate());
      }
      System.out.println("masa server number: " + builder.getMasaNumber());

      registrar = builder.build(Integer.parseInt(port));

      DomainCA ca =
          new DomainCA(domainName, domainCred.getPrivateKey(), domainCred.getCertificate());
      registrar.setDomainCA(ca);
    } catch (Exception e) {
      System.err.println("error: " + e.getMessage());
      helper.printHelp(HELP_FORMAT, options);
      return;
    }

    registrar.start();
    System.out.println("registrar listening at " + registrar.getListenPort());
  }
}

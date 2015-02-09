/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.ejbca.core.protocol.ws.client;

import org.ejbca.core.protocol.ws.client.gen.AuthorizationDeniedException_Exception;
import org.ejbca.core.protocol.ws.client.gen.EjbcaException_Exception;
import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.ejbca.ui.cli.IAdminCommand;
import org.ejbca.ui.cli.IllegalAdminCommandException;

public class GenerateCryptoTokenKeysCommand extends EJBCAWSRABaseCommand implements IAdminCommand{

   private static final int ARG_TOKEN_NAME = 1;
   private static final int ARG_KEY_ALIAS = 2;
   private static final int ARG_KEY_SPEC = 3;
   
   GenerateCryptoTokenKeysCommand(String[] args) {
       super(args);
   }

   @Override
   public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
       if(args.length < 4){
           usage();
           System.exit(-1); // NOPMD, it's not a JEE app
       }
       
       try {
           getEjbcaRAWS().generateCryptoTokenKeys(args[ARG_TOKEN_NAME], args[ARG_KEY_ALIAS], args[ARG_KEY_SPEC]);
           getPrintStream().println("Key with alias '" + args[ARG_KEY_ALIAS] + "' for cryptotoken '" + args[ARG_TOKEN_NAME] + "' was generated successfully");
       } catch (AuthorizationDeniedException_Exception e) {
           getPrintStream().println("Error : " + e.getMessage());
       } catch (EjbcaException_Exception e) {
           getPrintStream().println("Error : " + e.getMessage());
       } catch (Exception e) {
           getPrintStream().println("Error : " + e.getMessage());
       }
       
   }

   @Override
   protected void usage() {
       getPrintStream().println("Command used to create a new crypto token");
       getPrintStream().println("Usage : generatecryptotokenkeys <TOKEN_NAME> <KEY_ALIAS> <KEY_SPECIFICATION>");
       getPrintStream().println();
       getPrintStream().println("TOKEN_NAME : The name of the crypto token where the keys should be generated.");
       getPrintStream().println("KEY_ALIAS : Key pair alias.");
       getPrintStream().println("KEY_SPECIFICATION : Key specification, for example 2048, secp256r1, DSA1024, gost3410, dstu4145");
   }
}
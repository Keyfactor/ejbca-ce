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

public class CreateCryptoTokenCommand extends EJBCAWSRABaseCommand implements IAdminCommand{

   private static final int ARG_TOKEN_NAME = 1;
   private static final int ARG_TOKEN_TYPE = 2;
   private static final int ARG_TOKEN_ACTIVATION_PIN = 3;
   private static final int ARG_AUTO_ACTIVATE = 4;
   private static final int ARG_ENABLE_KEY_EXPORT = 5;
   private static final int ARG_PKCS11_LIB_FILENAME = 6;
   private static final int ARG_PKCS11_SLOT_LABEL_TYPE = 7;
   private static final int ARG_PKCS11_SLOT_PROPERTY_VALUE = 8;
   //private static final int ARG_PKCS11_ATTRIBUTE_DATA = 9;
   
   CreateCryptoTokenCommand(String[] args) {
       super(args);
   }

   @Override
   public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
       if(args.length < 6){
           usage();
           System.exit(-1); // NOPMD, it's not a JEE app
       }
       
       if((args.length > 6) && (args.length < 9)) {
           getPrintStream().println("ERROR. Missing command line arguments.");
           getPrintStream().println();
           usage();
           System.exit(-1);
       }

       boolean autoActivation = Boolean.parseBoolean(args[ARG_AUTO_ACTIVATE]);
       boolean exportKeys = Boolean.parseBoolean(args[ARG_ENABLE_KEY_EXPORT]);
       try {
           getEjbcaRAWS().createCryptoToken(args[ARG_TOKEN_NAME], args[ARG_TOKEN_TYPE], args[ARG_TOKEN_ACTIVATION_PIN], autoActivation, exportKeys, 
                   args.length>6?args[ARG_PKCS11_LIB_FILENAME]:null, args.length>6?args[ARG_PKCS11_SLOT_LABEL_TYPE]:null, 
                   args.length>6?args[ARG_PKCS11_SLOT_PROPERTY_VALUE]:null, null);
           getPrintStream().println("Crypto token " + args[ARG_TOKEN_NAME] + " was created");
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
       getPrintStream().println("Usage : createcryptotoken <TOKEN_NAME> <TOKEN_TYPE> <ACTIVATION_PIN> <ENABLE_AUTO_ACTIVATION> <ENABLE_EXPORT_KEYS> " +
       		"[ <PKCS11_LIBRARY_FILE> <SLOT_REFERENCE_TYPE> <SLOT_REFERENCE_VALUE> <PKCS11_ATTRIBUTE_DATA> ]");
       getPrintStream().println();
       getPrintStream().println("TOKEN_NAME : The name of the crypto token.");
       getPrintStream().println("TOKEN_TYPE : Available types: SoftCryptoToken, PKCS11CryptoToken");
       getPrintStream().println("ACTIVATION_PIN : Pin code for the crypto token.");
       getPrintStream().println("ENABLE_AUTO_ACTIVATION : Set to true|false to allow|disallow whether crypto token should be autoactivated or not.");
       getPrintStream().println("ENABLE_EXPORT_KEYS : (SoftCryptoToken) Set to true|false to allow|disallow private key export.");
       getPrintStream().println("PKCS11_LIBRARY_FILE : (PKCS11CryptoToken) PKCS#11 library file. Required if type is PKCS11CryptoToken");
       getPrintStream().println("SLOT_REFERENCE_TYPE : (PKCS11CryptoToken) Slot Reference Type:");
       getPrintStream().println("          SLOT_LABEL - Slot Label");
       getPrintStream().println("          SLOT_INDEX - Slot Index");
       getPrintStream().println("          SLOT_NUMBER - Slot Number");
       getPrintStream().println("          SUN_FILE - Sun configuration file");
       getPrintStream().println("SLOT_REFERENCE_VALUE : (PKCS11CryptoToken) Slot reference.");
       getPrintStream().println("PKCS11_ATTRIBUTE_DATA : (Not implemented yet) (PKCS11CryptoToken) the CryptoToken attributes. For now, the value will be ignored but has to be set anyway");
       
   }
}
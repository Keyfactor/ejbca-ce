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

import java.io.File;
import java.io.FileInputStream;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Properties;

import org.cesecore.keys.token.PKCS11CryptoToken;
import org.cesecore.keys.token.SoftCryptoToken;
import org.ejbca.core.protocol.ws.client.gen.EjbcaException_Exception;
import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.ejbca.ui.cli.IAdminCommand;
import org.ejbca.ui.cli.IllegalAdminCommandException;
import org.ejbca.util.KeyValuePair;


/**
 * Creates new cryptotoken
 *
 * @version $Id: CaCertRequestCommand.java 19902 2014-09-30 14:32:24Z anatom $
 */
public class CreateCryptoTokenCommand extends EJBCAWSRABaseCommand implements IAdminCommand{

    private static final int ARG_CRYPTOTOKEN_NAME    = 1;
    private static final int ARG_CRYPTOTOKEN_TYPE    = 2;
    private static final int ARG_AUTO_ACTIVATE       = 3;
    private static final int ARG_ACTIVATION_PIN      = 4;
    private static final int ARG_PROPERTIES_FILE     = 5;
    
    /**
     * Creates a new instance of Command
     *
     * @param args command line arguments
     */
    public CreateCryptoTokenCommand(String[] args) {
        super(args);
    }

    /**
     * Runs the command
     *
     * @throws IllegalAdminCommandException Error in command args
     * @throws ErrorAdminCommandException Error running command
     */
    public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
        try {   
            if (args.length < 5 ) {
                getPrintStream().println("Error. Too few arguments: "+args.length);
                usage();
                System.exit(-1); // NOPMD, this is not a JEE app
            }
            
            String tokenName = args[ARG_CRYPTOTOKEN_NAME];
            String tokenType = args[ARG_CRYPTOTOKEN_TYPE];
            boolean autoActivate = Boolean.parseBoolean(args[ARG_AUTO_ACTIVATE]);
            String pin = args[ARG_ACTIVATION_PIN];
            ArrayList<KeyValuePair> properties = new ArrayList<KeyValuePair>();
            if(args.length > 5) {
                Properties props = new Properties();
                props.load(new FileInputStream(new File(args[ARG_PROPERTIES_FILE])));
                
                Iterator<Object> itr = props.keySet().iterator();
                while(itr.hasNext()) {
                    String key = (String) itr.next();
                    properties.add(new KeyValuePair(key, props.getProperty(key)));
                }
                
            }

            //getPrintStream().println("autoactivate: " + autoActivate);
            getEjbcaRAWS().createCryptoToken(tokenName, tokenType, pin, autoActivate, properties);
            getPrintStream().println("Create new cryptotoken: " + tokenName);
        } catch (Exception e) {
            if (e instanceof EjbcaException_Exception) {
                EjbcaException_Exception e1 = (EjbcaException_Exception)e;
                getPrintStream().println("Error code is: " + e1.getFaultInfo().getErrorCode().getInternalErrorCode());
            }
            throw new ErrorAdminCommandException(e);
        }
        
    }

    protected void usage() {
        getPrintStream().println("Command used to create a new cryptotoken");
        getPrintStream().println("Usage : createcryptotoken <cryptotokenName> <cryptotokenType> <autoActivate> <activationPin> " +
        		"[<pathToCryptoTokenPropertiesFile>]");
        getPrintStream().println();
        getPrintStream().println("cryptotokenName: The name of the new crypto token.");
        getPrintStream().println("cryptotokenType: Can be one of: " + SoftCryptoToken.class.getSimpleName() + ", " + PKCS11CryptoToken.class.getSimpleName());
        getPrintStream().println("autoActivate: Set to true|false to allow|disallow whether crypto token should be autoactivated or not.");
        getPrintStream().println("activationPin: Pin code for the crypto token.");
        getPrintStream().println("pathToCryptoTokenPropertiesFile: The path to a .properties file containing the new cryptotoken properties. Optional");
        /*
        StringBuilder sb = new StringBuilder();
        sb.append("Slot Reference Types:\n");
        for (Pkcs11SlotLabelType type : Pkcs11SlotLabelType.values()) {
            sb.append("    " + type.getKey() + " - " + type.getDescription() + "\n");
        }
        */
    }
}

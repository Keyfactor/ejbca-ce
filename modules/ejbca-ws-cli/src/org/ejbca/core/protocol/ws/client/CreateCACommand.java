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

import org.apache.commons.lang.StringUtils;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.ejbca.core.protocol.ws.client.gen.EjbcaException_Exception;
import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.ejbca.ui.cli.IAdminCommand;
import org.ejbca.ui.cli.IllegalAdminCommandException;
import org.ejbca.core.protocol.ws.client.gen.KeyValuePair;


/**
 * Creates new CA
 *
 * @version $Id: CaCertRequestCommand.java 19902 2014-09-30 14:32:24Z anatom $
 */
public class CreateCACommand extends EJBCAWSRABaseCommand implements IAdminCommand{

    private static final int ARG_CANAME                     = 1;
    private static final int ARG_CADN                       = 2;
    private static final int ARG_CATYPE                     = 3;
    private static final int ARG_VALIDITY_IN_DAYS           = 4;
    private static final int ARG_CERT_PROFILE               = 5;
    private static final int ARG_SIGN_ALG                   = 6;
    private static final int ARG_SIGNED_BY_CAID             = 7;
    private static final int ARG_CRYPTOTOKEN_NAME           = 8;
    private static final int ARG_PURPOSE_KEY_MAPPING_PATH   = 9;
    private static final int ARG_CA_PROPERTIES_PATH         = 10;
    
    /**
     * Creates a new instance of Command
     *
     * @param args command line arguments
     */
    public CreateCACommand(String[] args) {
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
            if (args.length < 10 ) {
                getPrintStream().println("Error. Too few arguments: "+args.length);
                usage();
                System.exit(-1); // NOPMD, this is not a JEE app
            }

            String caname = args[ARG_CANAME];
            String cadn = args[ARG_CADN];
            String catype = args[ARG_CATYPE];
            String validityEncoded = args[ARG_VALIDITY_IN_DAYS];
            String certprofile = StringUtils.equalsIgnoreCase(args[ARG_CERT_PROFILE], "null")? null : args[ARG_CERT_PROFILE];
            String signalg = args[ARG_SIGN_ALG];
            int signedByCAId = Integer.parseInt(args[ARG_SIGNED_BY_CAID]);
            String cryptotokenName = args[ARG_CRYPTOTOKEN_NAME];

            Properties mapping = new Properties();
            mapping.load(new FileInputStream(new File(args[ARG_PURPOSE_KEY_MAPPING_PATH])));
            ArrayList<KeyValuePair> purposeKeyMapping = getKeyValuePairListFromProperties(mapping);
            
            ArrayList<KeyValuePair> caproperties = new ArrayList<KeyValuePair>();
            if(args.length > 10) {
                Properties props = new Properties();
                props.load(new FileInputStream(new File(args[ARG_CA_PROPERTIES_PATH])));
                caproperties = getKeyValuePairListFromProperties(props);
            }
                        
            long validityInDays = Long.valueOf(validityEncoded);
            getEjbcaRAWS().createCA(caname, cadn, catype, validityInDays, certprofile, signalg, signedByCAId, cryptotokenName, 
                    purposeKeyMapping, caproperties);
            getPrintStream().println("Create new CA: " + caname);
        } catch (Exception e) {
            if (e instanceof EjbcaException_Exception) {
                EjbcaException_Exception e1 = (EjbcaException_Exception)e;
                getPrintStream().println("Error code: " + e1.getFaultInfo().getErrorCode().getInternalErrorCode());
            }
            ErrorAdminCommandException adminexp = new ErrorAdminCommandException(e);
            getPrintStream().println("Error message: " + adminexp.getLocalizedMessage());
        }
        
    }

    protected void usage() {
        getPrintStream().println("Command used to create a new CA with a specific existing cryptotoken");
        getPrintStream().println("Usage : createca <caname> <cadn> <catype> <validity> <certprofile> <signalg> <signedByCAID> " +
        		"<cryptotokenName> <pathToKeyPurposeMappingFile> [<pathToCAPropertiesFile>]");
        getPrintStream().println();
        getPrintStream().println("'caname' is the name of the CA");
        getPrintStream().println("'cadn' is the subjectDN av the CA");
        getPrintStream().println("'catype' can be either 'x509' or 'cvc'.");
        getPrintStream().println("'validity' is the validity of the CA in days");
        getPrintStream().println("'certprofile' the certificate profile that should be used when issueing the CA certificate instead of the default profiles ROOTCA or SUBCA. Use 'null' for default profiles.");
        
        StringBuilder availableSignAlgs = new StringBuilder();
        for (String algorithm : AlgorithmConstants.AVAILABLE_SIGALGS) {
            availableSignAlgs.append((availableSignAlgs.length() == 0 ? "" : ", ") + algorithm);
        }
        getPrintStream().println("'signalg' can be any of: " + availableSignAlgs);
        getPrintStream().println("'signedByCAID' is the ID of a CA that will sign this CA. Use '1' for self signed CA (i.e. a root CA). CAs created using the WS cannot be signed by external CAs");
        getPrintStream().println("'cryptotokenName' is the name of the cryptotoken associated with the CA");
        getPrintStream().println("'pathToKeyPurposeMappingFile' is the path to a .properties file containing the mapping of the cryptotoken keys and their purpose");
        getPrintStream().println("'pathToCAPropertiesFile' is the path to a .properties file containing additional CA properties. Optional");
        getPrintStream().println();
        getPrintStream().println("Please note that the policy ID is specified in the properties file containing additional properties with the property key 'policyid'.");
        getPrintStream().println("The policy ID can be 'null' if no Certificate Policy extension should be present, or\nobjectID as '2.5.29.32.0' or objectID and cpsurl "
                + "as \"2.5.29.32.0 http://foo.bar.com/mycps.txt\". You can add multiple policies such as "
                + "\"2.5.29.32.0 http://foo.bar.com/mycps.txt 1.1.1.1.1 http://foo.bar.com/111cps.txt\".");
    }
    
    private ArrayList<KeyValuePair> getKeyValuePairListFromProperties(Properties properties) {
        ArrayList<KeyValuePair> kvlist = new ArrayList<KeyValuePair>();
        Iterator<Object> itr = properties.keySet().iterator();
        while(itr.hasNext()) {
            String key = (String) itr.next();
            KeyValuePair kvp = new KeyValuePair();
            kvp.setKey(key);
            kvp.setValue(properties.getProperty(key));
            kvlist.add(kvp);
        }
        return kvlist;
    }
}

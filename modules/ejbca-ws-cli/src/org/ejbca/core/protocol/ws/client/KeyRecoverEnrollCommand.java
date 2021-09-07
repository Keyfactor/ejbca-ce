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
import java.io.FileOutputStream;
import java.io.IOException;

import org.cesecore.util.Base64;
import org.ejbca.core.protocol.ws.client.gen.ApprovalException_Exception;
import org.ejbca.core.protocol.ws.client.gen.AuthorizationDeniedException_Exception;
import org.ejbca.core.protocol.ws.client.gen.CADoesntExistsException_Exception;
import org.ejbca.core.protocol.ws.client.gen.EjbcaException_Exception;
import org.ejbca.core.protocol.ws.client.gen.KeyStore;
import org.ejbca.core.protocol.ws.client.gen.NotFoundException_Exception;
import org.ejbca.core.protocol.ws.client.gen.WaitingForApprovalException_Exception;
import org.ejbca.core.protocol.ws.common.KeyStoreHelper;
import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.ejbca.ui.cli.IAdminCommand;
import org.ejbca.ui.cli.IllegalAdminCommandException;

/**
 * 
 * @version $Id$
 *
 */
public class KeyRecoverEnrollCommand extends EJBCAWSRABaseCommand implements IAdminCommand {

    private static final int ARG_USERNAME                 = 1;
    private static final int ARG_CERTSNINHEX              = 2;
    private static final int ARG_ISSUERDN                 = 3;
    private static final int ARG_PASSWORD                 = 4;
    
    /**
     * 'hardtokensn' is deprecated since 7.1.0, just use NONE here. Is kept for client compatibility for now.
     */
    @Deprecated
    private static final int ARG_HARDTOKENSN              = 5;
    
    private static final int ARG_OUTPUTPATH               = 6;
    
    private static final byte PKCS12_MAGIC = (byte)48;
    private static final byte JKS_MAGIC = (byte)(0xfe);
    
    KeyRecoverEnrollCommand(String[] args) {
        super(args);
        
    }

    @Override
    public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
        try {
            if(args.length < 6 || args.length > 7) { // TODO
                getPrintStream().println("Unexpected number of parameters");
                usage();
                System.exit(-1); // NOPMD, it's not a JEE app
            }
            
            String username = args[ARG_USERNAME];
            String certSn = args[ARG_CERTSNINHEX];
            String issuerDn = args[ARG_ISSUERDN];
            String password = args[ARG_PASSWORD];
            
            try {
                KeyStore result = getEjbcaRAWS().keyRecoverEnroll(username, certSn, issuerDn, password, null);
                
                if(result==null) {
                    getPrintStream().println("No keystore could be generated for user, check server logs for error.");
                } else {
                    String filepath = username;
                    String outputPath = null;
                    
                    if (args.length == 7) {
                      outputPath = getOutputPath(args[ARG_OUTPUTPATH]);
                    }
                    
                    if (outputPath != null) {
                        filepath = outputPath + "/" + filepath;
                    }
                    final byte[] keyStoreBytes = Base64.decode(result.getKeystoreData());
                    String keyStoreType;
                    if (keyStoreBytes[0] == PKCS12_MAGIC) {
                        keyStoreType = "PKCS12";
                        filepath = filepath + ".p12";
                    } else if (keyStoreBytes[0] == JKS_MAGIC) {
                        keyStoreType = "JKS";
                        filepath = filepath + ".jks";
                    } else {
                        throw new IOException("Unsupported keystore type. Must be PKCS12 or JKS");
                    }
                    
                    FileOutputStream fos = new FileOutputStream(filepath);
                    java.security.KeyStore ks = KeyStoreHelper.getKeyStore(result.getKeystoreData(), keyStoreType, password);
                    ks.store(fos, password.toCharArray());
                    fos.close();                    
                    getPrintStream().println("Key recovery sucessfull!\nKeystore generated, written to " + filepath);
                }
            } catch (AuthorizationDeniedException_Exception e) {
                getPrintStream().println("Authentication failed :\n" + e.getMessage());
            } catch (WaitingForApprovalException_Exception e) {
                getPrintStream().println(e.getMessage());
            } catch (ApprovalException_Exception e) {
                getPrintStream().println(e.getMessage());
            } catch (CADoesntExistsException_Exception e) {
                getPrintStream().println(e.getMessage());
            } catch (NotFoundException_Exception e) {
                getPrintStream().println(e.getMessage());
            } catch (EjbcaException_Exception e) {
                getPrintStream().println(e.getMessage());
            }
            
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }

    private String getOutputPath(String outputpath) {
        File dir = new File(outputpath);
        if(!dir.exists()){
            getPrintStream().println("Error : Output directory doesn't seem to exist.");
            System.exit(-1); // NOPMD, it's not a JEE app
        }
        if(!dir.isDirectory()){
            getPrintStream().println("Error : Output directory doesn't seem to be a directory.");
            System.exit(-1); // NOPMD, it's not a JEE app           
        }
        if(!dir.canWrite()){
            getPrintStream().println("Error : Output directory isn't writeable.");
            System.exit(-1); // NOPMD, it's not a JEE app

        }
        return outputpath;
    }
    
    @Override
    protected void usage() {
        getPrintStream().println("Command used for key recovery and enroll");
        getPrintStream().println("Usage : keyrecover <username> <certSerialNr> <issuerDN> <password> <hardtokensn (or NONE)> <outputpath (optional)>");
        getPrintStream().println("\"hardtokensn\" is deprecated since 7.1.0, just use NONE here");
    }
}

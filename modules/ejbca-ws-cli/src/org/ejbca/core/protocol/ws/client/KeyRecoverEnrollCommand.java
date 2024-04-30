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
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import com.keyfactor.util.Base64;

import org.bouncycastle.util.Properties;
import org.cesecore.certificates.certificate.CertificateConstants;
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
 * Calling EjbcaWS.keyRecoverEnroll to recover keys to be stored as a keystore file. 
 */
public class KeyRecoverEnrollCommand extends EJBCAWSRABaseCommand implements IAdminCommand {

    private static final int ARG_USERNAME                 = 1;
    private static final int ARG_CERTSNINHEX              = 2;
    private static final int ARG_ISSUERDN                 = 3;
    private static final int ARG_PASSWORD                 = 4;
    
    /**
     * 'hardtokensn' is deprecated since 7.1.0, just use NONE here. Is kept for client compatibility for now.
     */
    @SuppressWarnings("unused")
    @Deprecated
    private static final int ARG_HARDTOKENSN              = 5;
    
    private static final int ARG_OUTPUTPATH               = 6;
    
    KeyRecoverEnrollCommand(String[] args) {
        super(args);
        
    }

    @Override
    public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
        try {
            if (args.length < 6 || args.length > 7) { // TODO
                getPrintStream().println("Unexpected number of parameters");
                usage();
                System.exit(-1); // NOPMD, it's not a JEE app
            }

            String username = args[ARG_USERNAME];
            String certSn = args[ARG_CERTSNINHEX];
            String issuerDn = args[ARG_ISSUERDN];
            String password = args[ARG_PASSWORD];

            try {
                try {

                    Properties.setThreadOverride(CertificateConstants.ENABLE_UNSAFE_RSA_KEYS, true);
                    KeyStore result = getEjbcaRAWS().keyRecoverEnroll(username, certSn, issuerDn, password, null);

                    if (result == null) {
                        getPrintStream().println("No keystore could be generated for user, check server logs for error.");
                    } else {
                        String filepath = username;
                        String extension;
                        String outputPath = null;

                        if (args.length == 7) {
                            outputPath = getOutputPath(args[ARG_OUTPUTPATH]);
                        }

                        if (outputPath != null) {
                            filepath = outputPath + "/" + username;
                        }
                        final byte[] keyStoreBytes = Base64.decode(result.getKeystoreData());
                        final String type;
                        // Keystore type is stored in the end entity, but we don't want an extra roundtrip to read that
                        if (keyStoreBytes[0] == KeyStoreHelper.PKCS12_MAGIC) {
                            extension = ".p12";
                            type = "PKCS12";
                        } else if (keyStoreBytes[0] == KeyStoreHelper.JKS_MAGIC) {
                            extension = ".jks";
                            type = "JKS";
                        } else if (keyStoreBytes[0] == KeyStoreHelper.PEM_MAGIC) {
                            extension = ".pem";
                            type = "PEM";
                        } else {
                            throw new IOException("Unsupported keystore type. Must be PKCS12 or JKS");
                        }

                        // Double check that the returned keystore is OK before storing it, this is just a helper for 
                        // to detect issues
                        try {
                            // We can't load a PEM file as a keystore
                            if (!"PEM".equals(type)) {
                                try {
                                    KeyStoreHelper.getKeyStore(result.getKeystoreData(), type, password);
                                } catch (IOException e) {
                                    // It may be a BCFKS that we detected as a P12 (since they have the same magic byte)
                                    KeyStoreHelper.getKeyStore(result.getKeystoreData(), "BCFKS", password);
                                    // Ok, it was a bcfks, change the filename
                                    extension = ".bcfks";
                                }                                
                            }
                            Files.write(Path.of(filepath + extension), keyStoreBytes);
                            getPrintStream().println("Key recovery sucessfull!\nKeystore generated, written to " + filepath + extension);
                        } catch (CertificateException | NoSuchAlgorithmException | IOException | KeyStoreException e) {
                            Files.write(Path.of(filepath + extension), keyStoreBytes);
                            e.printStackTrace();
                            getPrintStream().println("Recovered keystore can not be loaded as a " + type + ". " + e.getMessage());
                            getPrintStream().println("Keystore bytes written to " + filepath + extension);
                        }
                    }
                } catch (AuthorizationDeniedException_Exception e) {
                    getPrintStream().println("Authentication failed :\n" + e.getMessage());
                } catch (WaitingForApprovalException_Exception | ApprovalException_Exception | CADoesntExistsException_Exception
                        | NotFoundException_Exception | EjbcaException_Exception e) {
                    getPrintStream().println(e.getMessage());
                }
            } finally {
                Properties.removeThreadOverride(CertificateConstants.ENABLE_UNSAFE_RSA_KEYS);
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

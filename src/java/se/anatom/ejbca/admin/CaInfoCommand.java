/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
 
package se.anatom.ejbca.admin;

import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;

import se.anatom.ejbca.util.CertTools;


/**
 * Gets and prints info about the CA.
 *
 * @version $Id: CaInfoCommand.java,v 1.10 2004-10-13 07:14:45 anatom Exp $
 */
public class CaInfoCommand extends BaseCaAdminCommand {
    /**
     * Creates a new instance of CaInfoCommand
     *
     * @param args command line arguments
     */
    public CaInfoCommand(String[] args) {
        super(args);
    }

    /**
     * Runs the command
     *
     * @throws IllegalAdminCommandException Error in command args
     * @throws ErrorAdminCommandException Error running command
     */
    public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
        if (args.length < 2) {
           String msg = "Usage: CA info <caname>";               
           throw new IllegalAdminCommandException(msg);
        }
        try {            
            String caname = args[1];
            ArrayList chain = new ArrayList(getCertChain(caname));

            if (chain.size() < 2)
              getOutputStream().println("This is a Root CA.");
            else
              getOutputStream().println("This is a subordinate CA.");
              
              getOutputStream().println("Size of chain: " + chain.size());
            if (chain.size() > 0) {
                X509Certificate rootcert = (X509Certificate)chain.get(chain.size()-1);
                getOutputStream().println("Root CA DN: "+CertTools.getSubjectDN(rootcert));
                getOutputStream().println("Certificate valid from: "+rootcert.getNotBefore().toString());
                getOutputStream().println("Certificate valid to: "+rootcert.getNotAfter().toString());
                getOutputStream().println("Root CA keysize: "+((RSAPublicKey)rootcert.getPublicKey()).getModulus().bitLength());            
                for(int i = chain.size()-2; i>=0; i--){                                          
                    X509Certificate cacert = (X509Certificate)chain.get(i);
                    getOutputStream().println("CA DN: "+CertTools.getSubjectDN(cacert));
                    getOutputStream().println("Certificate valid from: "+cacert.getNotBefore().toString());
                    getOutputStream().println("Certificate valid to: "+cacert.getNotAfter().toString());
                    getOutputStream().println("CA keysize: "+((RSAPublicKey)cacert.getPublicKey()).getModulus().bitLength());

                }                
            }
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    } // execute
}

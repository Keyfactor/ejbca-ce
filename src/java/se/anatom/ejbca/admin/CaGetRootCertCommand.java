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

import java.io.*;
import java.util.ArrayList;
import java.security.cert.X509Certificate;

import se.anatom.ejbca.util.CertTools;

/**
 * Export root CA certificate.
 *
 * @version $Id: CaGetRootCertCommand.java,v 1.13 2004-04-16 07:38:57 anatom Exp $
 */
public class CaGetRootCertCommand extends BaseCaAdminCommand {
    /**
     * Creates a new instance of CaGetRootCertCommand
     *
     * @param args command line arguments
     */
    public CaGetRootCertCommand(String[] args) {
        super(args);
    }

    /**
     * Runs the command
     *
     * @throws IllegalAdminCommandException Error in command args
     * @throws ErrorAdminCommandException Error running command
     */
    public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
		
        if (args.length < 3) {		
            String msg = "Save root CA certificate (PEM- or DER-format) to file.\n";
            msg += "Usage: CA getrootcert <caname> <filename> <-der>";
            throw new IllegalAdminCommandException(msg);
        }		
		
        String caname = args[1];
        String filename = args[2];
        boolean pem = true;
        if (args.length > 3) {
            if (("-der").equals(args[3])) {
                pem = false;
            }
        }
        	
		System.out.flush();
        try {
            ArrayList chain = new ArrayList(getCertChain(caname));
            if (chain.size() > 0) {
                X509Certificate rootcert = (X509Certificate)chain.get(chain.size()-1);
 
                FileOutputStream fos = new FileOutputStream(filename);
                if (pem) {		
                    fos.write(CertTools.getPEMFromCerts(chain));
                } else {					
                    fos.write(rootcert.getEncoded());
                }				
                fos.close();
				System.out.println("Wrote Root CA certificate to '" + filename + "'");
            } else {
                System.out.println("No CA certificate found.");
            }
        } catch (Exception e) {			
            throw new ErrorAdminCommandException(e);
        }        
    } // execute
}

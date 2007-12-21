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
 
package org.ejbca.ui.cli;

import java.io.FileOutputStream;

import javax.naming.Context;

import org.apache.commons.lang.StringUtils;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionHome;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionRemote;
import org.ejbca.util.CertTools;


/**
 * Retrieves the latest CRL from the CA.
 *
 * @version $Id: CaGetCrlCommand.java,v 1.3 2007-12-21 09:02:33 anatom Exp $
 */
public class CaGetCrlCommand extends BaseCaAdminCommand {
    /**
     * Creates a new instance of CaGetCrlCommand
     *
     * @param args command line arguments
     */
    public CaGetCrlCommand(String[] args) {
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
				throw new IllegalAdminCommandException("Retrieves CRL in DER format.\nUsage: CA getcrl [-delta] <caname> <outfile> (-pem)");
			}
			try {
                String caname = args[1];
                int deltaSelector = 0;
                if (StringUtils.equals(args[1], "-delta")) {
                	deltaSelector = 1;
                }
				String outfile = args[2 + deltaSelector];

                boolean pem = false;
                if (args.length > 3) {
                    if (("-pem").equals(args[3 + deltaSelector])) {
                        pem = true;
                    }
                }
                
                String issuerdn = getIssuerDN(caname);
				Context context = getInitialContext();
				ICertificateStoreSessionHome storehome = (ICertificateStoreSessionHome) javax.rmi.PortableRemoteObject.narrow(context.lookup("CertificateStoreSession"),ICertificateStoreSessionHome.class);
				ICertificateStoreSessionRemote store = storehome.create();
				byte[] crl = store.getLastCRL(administrator, issuerdn, (deltaSelector > 0));
				FileOutputStream fos = new FileOutputStream(outfile);
                if (pem) {		
                    fos.write(CertTools.getPEMFromCrl(crl));
                } else {					
                	fos.write(crl);
                }
				fos.close();
				getOutputStream().println("Wrote latest " + (deltaSelector == 0 ? "" : "delta ") + "CRL to " + outfile + ".");
			} catch (Exception e) {
				throw new ErrorAdminCommandException(e);
			}
    } // execute

}

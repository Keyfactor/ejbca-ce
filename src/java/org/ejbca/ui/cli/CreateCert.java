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
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collection;

import org.ejbca.core.model.log.Admin;
import org.ejbca.core.protocol.IRequestMessage;
import org.ejbca.core.protocol.IResponseMessage;
import org.ejbca.core.protocol.PKCS10RequestMessage;
import org.ejbca.core.protocol.X509ResponseMessage;
import org.ejbca.util.CertTools;
import org.ejbca.util.FileTools;
import org.ejbca.util.RequestMessageUtils;

/**
 * Implements the password encryption mechanism
 *
 * @version $Id: EncryptPwd.java 5585 2008-05-01 20:55:00Z anatom $
 */
public class CreateCert extends BaseCommand {

	public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
        if ( (args.length < 4) || ((args.length > 4)) ) {
            getOutputStream().println("Usage: createcert <username> <password> <csr.pem> <cert.pem>");
            getOutputStream().println("<csr.pem> must be a PKCS#10 request in PEM format.");
            getOutputStream().println("The issued certificate will be written to <cert.pem>.");
            return;
 	    }	
          
        String username = args[0];
        String password = args[1];
        String csr = args[2];
        String certf = args[3];
        
        try {
			byte[] bytes = FileTools.readFiletoBuffer(csr);
			IRequestMessage req = RequestMessageUtils.parseRequestMessage(bytes);
			if (req instanceof PKCS10RequestMessage) {
				PKCS10RequestMessage p10req = (PKCS10RequestMessage) req;
				p10req.setUsername(username);
				p10req.setPassword(password);
			} else {
				getOutputStream().println("Input file '"+csr+"' is not a PKCS#10 request.");
				return;
			}
			Class responseClass = Class.forName(X509ResponseMessage.class.getName());
			// Call signsession to create a certificate
			IResponseMessage resp = getSignSession().createCertificate(administrator, req, responseClass);
			byte[] respBytes = resp.getResponseMessage();
			// Convert to PEM
			Certificate cert = CertTools.getCertfromByteArray(respBytes);
			Collection certs = new ArrayList();
			certs.add(cert);
			byte[] pembytes = CertTools.getPEMFromCerts(certs);
			// Write the resulting cert to file
			FileOutputStream fos = new FileOutputStream(certf);
			fos.write(pembytes);
			fos.close();
			getOutputStream().println("PEM certificate written to file '"+certf+"'");
		} catch (Exception e) {
			throw new ErrorAdminCommandException(e);
		}
        
	}
	
	/**
     * main class
     *
     * @param args command line arguments
     */
    public static void main(String[] args) {
    	
    	CreateCert cmd = new CreateCert();
    	cmd.init(args, Admin.TYPE_CACOMMANDLINE_USER, "cli", System.out);
    	try {
        	cmd.execute();    		
    	} catch (Exception e) {
    		e.printStackTrace();
    	}
    	
    }
}

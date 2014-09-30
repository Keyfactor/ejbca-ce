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
 
package org.ejbca.core.protocol.xkms.client;

import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;

import org.cesecore.util.CertTools;
import org.ejbca.core.protocol.xkms.common.XKMSConstants;
import org.ejbca.core.protocol.xkms.common.XKMSUtil;
import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.ejbca.ui.cli.IAdminCommand;
import org.ejbca.ui.cli.IllegalAdminCommandException;
import org.w3._2000._09.xmldsig_.KeyInfoType;
import org.w3._2000._09.xmldsig_.X509DataType;
import org.w3._2002._03.xkms_.KeyBindingType;
import org.w3._2002._03.xkms_.ObjectFactory;
import org.w3._2002._03.xkms_.RevokeRequestType;
import org.w3._2002._03.xkms_.RevokeResultType;


/**
 * Performes KRSS revoke calls to an web service.
 *
 * @version $Id$
 * @author Philip Vendil
 */
public class RevokeCommand extends XKMSCLIBaseCommand implements IAdminCommand{

	private ObjectFactory xKMSObjectFactory = new ObjectFactory();
	private org.w3._2000._09.xmldsig_.ObjectFactory sigFactory = new org.w3._2000._09.xmldsig_.ObjectFactory();
	
	private static final int ARG_CERT               = 1;
	private static final int ARG_CERTENCODING       = 2;
	private static final int ARG_REVOCATIONCODE     = 3;	

    public RevokeCommand(String[] args) {
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
           
            if(args.length != 4 ){
            	usage();
            	System.exit(-1); // NOPMD, it's not a JEE app
            }  
  
            String certEncoding = getCertEncoding(args[ARG_CERTENCODING]);            
            Certificate orgCert = getCert(args[ARG_CERT],certEncoding);
            String revokationCode = args[ARG_REVOCATIONCODE];
                                                            
            String reqId = genId();
            RevokeRequestType revokeRequestType = xKMSObjectFactory.createRevokeRequestType();
            revokeRequestType.setId(reqId);
            revokeRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CHAIN);            
            revokeRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_PRIVATEKEY);
            
            X509DataType x509DataType = sigFactory.createX509DataType();
            x509DataType.getX509IssuerSerialOrX509SKIOrX509SubjectName().add(sigFactory.createX509DataTypeX509Certificate(orgCert.getEncoded()));
            KeyInfoType keyInfoType = sigFactory.createKeyInfoType();
            keyInfoType.getContent().add(sigFactory.createX509Data(x509DataType));
            
            String keyBindingId = "_" + CertTools.getSerialNumber(orgCert).toString();
            KeyBindingType keyBindingType = xKMSObjectFactory.createKeyBindingType();                
            keyBindingType.setKeyInfo(keyInfoType);
            keyBindingType.setId(keyBindingId);
            revokeRequestType.setRevokeKeyBinding(keyBindingType);  
            
            byte[] first = XKMSUtil.getSecretKeyFromPassphrase(revokationCode, true,20, XKMSUtil.KEY_REVOCATIONCODEIDENTIFIER_PASS1).getEncoded();
            revokeRequestType.setRevocationCode(first);           
            
            RevokeResultType revokeResultType = getXKMSInvoker().revoke(revokeRequestType, clientCert, privateKey, null,  keyBindingId);

            
            if (revokeResultType.getResultMajor().equals(XKMSConstants.RESULTMAJOR_SUCCESS) && revokeResultType.getResultMinor() == null) {
            	getPrintStream().println("Certificate " + CertTools.getSerialNumber(orgCert).toString(16) + " issued by " +
            			CertTools.getIssuerDN(orgCert) + " revoked successfully.");
            } else if (revokeResultType.getResultMajor().equals(XKMSConstants.RESULTMAJOR_SUCCESS) && revokeResultType.getResultMinor().equals(XKMSConstants.RESULTMINOR_INCOMPLETE)) {
            	getPrintStream().println("Certificate " + CertTools.getSerialNumber(orgCert).toString(16) + " issued by " +
            			CertTools.getIssuerDN(orgCert) + " successfully sent for approval.");
            } else {
            	displayRequestErrors(revokeResultType);
            }
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }

    private Certificate getCert(String filename, String certEncoding) {		
		Certificate retval = null;
		
		if(certEncoding.equals(ENCODING_PEM)){			
			try {
				Collection<Certificate> certs = CertTools.getCertsFromPEM(filename);
				if(certs.size() > 0){
					retval = (X509Certificate) certs.iterator().next();
				}
			} catch (Exception e) {}

		}
		if(certEncoding.equals(ENCODING_DER)){
			try {
				byte[] certdata = loadCert(filename);
				retval = CertTools.getCertfromByteArray(certdata);
			} catch (CertificateException e) {
			}
		}
		
		if(retval == null){
			getPrintStream().println("Error couldn't decode certificate " + filename);
	        usage();
	    	System.exit(-1); // NOPMD, it's not a JEE app
		}
		
		return retval;
	}

	private String getCertEncoding(String arg) {
		if(arg.equalsIgnoreCase(ENCODING_PEM)){
			return ENCODING_PEM;
		}
		
		if(arg.equalsIgnoreCase(ENCODING_DER)){
			return ENCODING_DER;
		}				
		
		getPrintStream().println("Illegal cert encoding(should be pem, der) : " + arg);
        usage();
    	System.exit(-1); // NOPMD, it's not a JEE app
    	return null;
	}

	private void displayRequestErrors(RevokeResultType revokeResultType) {
		if(revokeResultType.getResultMinor().equals(XKMSConstants.RESULTMINOR_NOMATCH)){
			getPrintStream().println("Error no user with given certificate could be found");
		}else if(revokeResultType.getResultMinor().equals(XKMSConstants.RESULTMINOR_NOAUTHENTICATION)){
			getPrintStream().println("Error password couldn't be verified");
		}else if(revokeResultType.getResultMinor().equals(XKMSConstants.RESULTMINOR_REFUSED)){
			getPrintStream().println("The user doesn't seem to have the right status or has already been revoked.");
		}else if(revokeResultType.getResultMajor().equals(XKMSConstants.RESULTMAJOR_RECIEVER) && 
				revokeResultType.getResultMinor().equals(XKMSConstants.RESULTMINOR_REFUSED)){
			getPrintStream().println("The request was refused. This could be caused by requesting an action twice if approvals are used.");
		}else{
			getPrintStream().println("Error occured during processing : " + revokeResultType.getResultMinor());
		}
	}

	protected void usage() {
		getPrintStream().println("Command used to revoke a certificate");
		getPrintStream().println("Usage : revoke <cert file name> <cert encoding (der|pem)> <revocation code>  \n\n");
		getPrintStream().println("Certificate encoding of the certificate about revoke, PEM and DER supported.\n");
        getPrintStream().println("Example: revoke revokecert.pem pem \"revoke phrase\"  ");
        getPrintStream().println("Revokes the certificate in  revokecert.pem");
        
            	        
	}


}

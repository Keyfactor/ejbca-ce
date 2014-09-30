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

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import org.cesecore.keys.util.KeyTools;
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
import org.w3._2002._03.xkms_.RecoverRequestType;
import org.w3._2002._03.xkms_.RecoverResultType;

/**
 * Performes KRSS recover calls to an web service.
 *
 * @version $Id$
 * @author Philip Vendil
 */
public class RecoverCommand extends XKMSCLIBaseCommand implements IAdminCommand{

	private ObjectFactory xKMSObjectFactory = new ObjectFactory();
	private org.w3._2000._09.xmldsig_.ObjectFactory sigFactory = new org.w3._2000._09.xmldsig_.ObjectFactory();
	
	private static final int ARG_CERT               = 1;
	private static final int ARG_CERTENCODING       = 2;
	private static final int ARG_PASSWORD           = 3;	
	private static final int ARG_ENCODING           = 4;
	private static final int ARG_OUTPUTPATH         = 5;

    public RecoverCommand(String[] args) {
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
           
            if(args.length < 5 || args.length > 6){
            	usage();
            	System.exit(-1); // NOPMD, this is not a JEE app
            }  
  
            String certEncoding = getCertEncoding(args[ARG_CERTENCODING]);            
            Certificate orgCert = getCert(args[ARG_CERT],certEncoding);
            String password = args[ARG_PASSWORD];
                                                
            String encoding = useEncoding(args[ARG_ENCODING]);
         
            String outputPath = "";
            if(args.length >= ARG_OUTPUTPATH +1){
            	if(args[ARG_OUTPUTPATH] != null){
            	  outputPath = args[ARG_OUTPUTPATH] + "/";            	            	
            	}
            }

            String reqId = genId();
            RecoverRequestType recoverRequestType = xKMSObjectFactory.createRecoverRequestType();
            recoverRequestType.setId(reqId);
            recoverRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CHAIN);            
            recoverRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_PRIVATEKEY);
            
            X509DataType x509DataType = sigFactory.createX509DataType();
            x509DataType.getX509IssuerSerialOrX509SKIOrX509SubjectName().add(sigFactory.createX509DataTypeX509Certificate(orgCert.getEncoded()));
            KeyInfoType keyInfoType = sigFactory.createKeyInfoType();
            keyInfoType.getContent().add(sigFactory.createX509Data(x509DataType));
            
            String keyBindingId = "_" + CertTools.getSerialNumber(orgCert).toString();
            KeyBindingType keyBindingType = xKMSObjectFactory.createKeyBindingType();                
            keyBindingType.setKeyInfo(keyInfoType);
            keyBindingType.setId(keyBindingId);
            recoverRequestType.setRecoverKeyBinding(keyBindingType);  
            
           
            
            RecoverResultType recoverResultType = getXKMSInvoker().recover(recoverRequestType, clientCert, privateKey, password,  keyBindingId);

            
            if(recoverResultType.getResultMajor().equals(XKMSConstants.RESULTMAJOR_SUCCESS) && 
               recoverResultType.getResultMinor() == null){
            
                if(recoverResultType.getKeyBinding().size() >0){
                	KeyBindingType keyBinding = recoverResultType.getKeyBinding().get(0);                	
                	List<X509Certificate> certs = getCertsFromKeyBinding(keyBinding);
                	  
                	X509Certificate userCert = getUserCert(certs);                	
                	certs.remove(userCert);
                	
                	if(recoverResultType.getPrivateKey() != null){
                		PrivateKey serverKey = XKMSUtil.getPrivateKeyFromEncryptedXML(recoverResultType.getPrivateKey(), password);
                		createKeyStore(userCert, certs, serverKey,password,encoding,outputPath);
                	}else{
            			getPrintStream().println("Error: Response didn't contain any private key");            	        
            	    	System.exit(-1); // NOPMD, this is not a JEE app
                	}

                }
   
            }else{
            	displayRequestErrors(recoverResultType);
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
	    	System.exit(-1); // NOPMD, this is not a JEE app
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
    	System.exit(-1); // NOPMD, this is not a JEE app
    	return null;
	}

	private X509Certificate getUserCert(Collection<X509Certificate> certs) {
		X509Certificate retval = null;
		Iterator<X509Certificate> iter = certs.iterator();
		while(iter.hasNext()){
			X509Certificate next = iter.next();
			if(next.getBasicConstraints() == -1){
				retval = next;
				break;
			}
		}
    	
		return retval;
	}

	private void createKeyStore(X509Certificate userCert, List<X509Certificate> caCerts, PrivateKey privKey, String password, String encoding, String outputPath) throws Exception {
		boolean createJKS = false;
		boolean createPEM = false;
		if(encoding.equals(ENCODING_JKS)){
			createJKS = true;
		}
		if(encoding.equals(ENCODING_PEM)){
			createPEM = true;
		}
		
        String alias = getAlias(userCert);
        
        Certificate[] caChain = new Certificate[caCerts.size()];
        for(int i=0;i<caCerts.size();i++){
        	caChain[i] = caCerts.get(i);
        }
		
        // Store keys and certificates in keystore.
        KeyStore ks = null;

        if (createJKS) {
            ks = KeyTools.createJKS(alias, privKey, password, userCert, caChain);
        } else {
            ks = KeyTools.createP12(alias, privKey,  userCert, caChain);
        }

        storeKeyStore(ks, alias, password, createJKS, createPEM, outputPath);
		
	}

	private String getAlias(X509Certificate userCert) {
        String alias = CertTools.getPartFromDN(CertTools.getSubjectDN(userCert), "CN");
        if (alias == null) {
        	alias = "myKey";
        }
		return alias;
	}

	private void displayRequestErrors(RecoverResultType recoverResultType) {
		if(recoverResultType.getResultMinor().equals(XKMSConstants.RESULTMINOR_NOMATCH)){
			getPrintStream().println("Error no user with given certificate could be found");
		}else
			if(recoverResultType.getResultMinor().equals(XKMSConstants.RESULTMINOR_NOAUTHENTICATION)){
				getPrintStream().println("Error password couldn't be verified");
			}else
				if(recoverResultType.getResultMinor().equals(XKMSConstants.RESULTMINOR_REFUSED)){
					getPrintStream().println("The user doesn't seem to have the wrong status.");
				}else{
					getPrintStream().println("Error occured during processing : " + recoverResultType.getResultMinor());
				}
	}

	
	/**
	 * Returns the encoding that the data should be written in
	 * @return
	 */
	private String useEncoding(String arg){
		if(arg.equalsIgnoreCase(ENCODING_PEM)){
			return ENCODING_PEM;
		}
		
		if(arg.equalsIgnoreCase(ENCODING_P12)){
			return ENCODING_P12;
		}
		
		if(arg.equalsIgnoreCase(ENCODING_JKS)){
			return ENCODING_JKS;
		}
		
		getPrintStream().println("Illegal encoding (should be pem, p12 or jks) : " + arg);
        usage();
    	System.exit(-1); // NOPMD, this is not a JEE app
    	return null;
	}

	protected void usage() {
		getPrintStream().println("Command used to recover the private key of a certificate");
		getPrintStream().println("Usage : recover <cert file name> <cert encoding (der|pem)> <password> <keystore encoding pem|p12|jks> <outputpath (optional)> \n\n");
		getPrintStream().println("Certificate encoding of the certificate about to recover key for, PEM and DER supported.\n");
		getPrintStream().println("Password used to authenticate to the XKMS service.\n");
        getPrintStream().println("Use pem, p12 or jks for encoding of the generated keystore.\n");
        getPrintStream().println("Outputpath specifies to which directory to write the keystore to, current directory is used if omitted\n\n");
        getPrintStream().println("Example: recover lostcert.pem pem \"foo123\"  pem");
        getPrintStream().println("Recovers the key to the lostcert.pem certificate and writes it in PEM encoding in the current directory");
        
            	        
	}
}

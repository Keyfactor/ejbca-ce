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

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import org.cesecore.keys.util.KeyTools;
import org.ejbca.core.protocol.xkms.common.XKMSConstants;
import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.ejbca.ui.cli.IAdminCommand;
import org.ejbca.ui.cli.IllegalAdminCommandException;
import org.w3._2000._09.xmldsig_.KeyInfoType;
import org.w3._2000._09.xmldsig_.X509DataType;
import org.w3._2002._03.xkms_.KeyBindingType;
import org.w3._2002._03.xkms_.ObjectFactory;
import org.w3._2002._03.xkms_.ReissueRequestType;
import org.w3._2002._03.xkms_.ReissueResultType;





/**
 * Performes KRSS reissue calls to an web service.
 *
 * @version $Id$
 * @author Philip Vendil
 */
public class ReissueCommand extends XKMSCLIBaseCommand implements IAdminCommand{

	private ObjectFactory xKMSObjectFactory = new ObjectFactory();
	private org.w3._2000._09.xmldsig_.ObjectFactory sigFactory = new org.w3._2000._09.xmldsig_.ObjectFactory();
	
	private static final int ARG_KEYSTORE           = 1;
	private static final int ARG_ALIAS              = 2;
	private static final int ARG_KEYSTOREPASSWORD   = 3;
	private static final int ARG_AUTHPASSWORD       = 4;
	private static final int ARG_ENCODING           = 5;
	private static final int ARG_OUTPUTPATH         = 6;
	    
    public ReissueCommand(String[] args) {
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
           
            if(args.length < 6 || args.length > 7){
            	usage();
            	System.exit(-1); // NOPMD, it's not a JEE app
            }  
            
            String keyPass = args[ARG_KEYSTOREPASSWORD];
            String authPass = args[ARG_AUTHPASSWORD];
            String alias = args[ARG_ALIAS];
            String encoding = useEncoding(args[ARG_ENCODING]); 
            
            KeyStore ks  = readKeyStore(args[ARG_KEYSTORE],encoding, keyPass);   
            X509Certificate orgCert = (X509Certificate) ks.getCertificate(alias);
            
            String outputPath = "";
            if(args.length >= ARG_OUTPUTPATH +1){
            	if(args[ARG_OUTPUTPATH] != null){
            	  outputPath = args[ARG_OUTPUTPATH] + "/";            	            	
            	}
            }

            String reqId = genId();
            ReissueRequestType reissueRequestType = xKMSObjectFactory.createReissueRequestType();
            reissueRequestType.setId(reqId);
            reissueRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CHAIN);
            
            String keyBindingId =  "_" + orgCert.getSerialNumber().toString();
            X509DataType x509DataType = sigFactory.createX509DataType();
            x509DataType.getX509IssuerSerialOrX509SKIOrX509SubjectName().add(sigFactory.createX509DataTypeX509Certificate(orgCert.getEncoded()));
            KeyInfoType keyInfoType = sigFactory.createKeyInfoType();
            keyInfoType.getContent().add(sigFactory.createX509Data(x509DataType));
            
            KeyBindingType keyBindingType = xKMSObjectFactory.createKeyBindingType();                
            keyBindingType.setKeyInfo(keyInfoType);
            keyBindingType.setId(keyBindingId);
            reissueRequestType.setReissueKeyBinding(keyBindingType);    
                               
            PrivateKey privateKey = (PrivateKey) ks.getKey(alias, keyPass.toCharArray());
            ReissueResultType reissueResultType = getXKMSInvoker().reissue(reissueRequestType, clientCert, privateKey, authPass, privateKey, keyBindingId);            
             
            if(reissueResultType.getResultMajor().equals(XKMSConstants.RESULTMAJOR_SUCCESS) && 
               reissueResultType.getResultMinor() == null){
            
                if(reissueResultType.getKeyBinding().size() >0){
                	KeyBindingType keyBinding = reissueResultType.getKeyBinding().get(0);                	
                	List<X509Certificate> certs = getCertsFromKeyBinding(keyBinding);
                	  
                	X509Certificate userCert = getUserCert(certs);                	
                	certs.remove(userCert);
                	    
                	createKeyStore(alias, userCert, certs,privateKey,keyPass,encoding,outputPath);

                }
   
            }else{
            	displayRequestErrors(reissueResultType);
            }
    
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }

    private KeyStore readKeyStore(String keystorefilename, String encoding, String keyPass)  {
        KeyStore ks = null;
        
        try {
        	if(encoding.equals(ENCODING_JKS)){
        		ks = KeyStore.getInstance("JKS");
        		ks.load(new FileInputStream(keystorefilename), keyPass.toCharArray());
        	}
        	
        	if(encoding.equals(ENCODING_P12)){
        		ks = KeyStore.getInstance("PKCS12");
        		ks.load(new FileInputStream(keystorefilename), keyPass.toCharArray());
        	}
        } catch (Exception e) {
    		getPrintStream().println("Error reading keystore " + keystorefilename + " from file : " + e.getMessage());
            usage();
        	System.exit(-1); // NOPMD, it's not a JEE app
		}
    	
    	
		return ks;
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

	private void createKeyStore(String alias, X509Certificate userCert, List<X509Certificate> caCerts, PrivateKey privKey, String password, String encoding, String outputPath) throws Exception {
		boolean createJKS = false;		
		if(encoding.equals(ENCODING_JKS)){
			createJKS = true;
		}	        
        
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

        storeKeyStore(ks, alias, password, createJKS, false, outputPath);
		
	}



	private void displayRequestErrors(ReissueResultType reissueResultType) {
		if(reissueResultType.getResultMinor().equals(XKMSConstants.RESULTMINOR_NOMATCH)){
			getPrintStream().println("Error no user could be found for the given certiifcate.");
		}else
			if(reissueResultType.getResultMinor().equals(XKMSConstants.RESULTMINOR_NOAUTHENTICATION)){
				getPrintStream().println("Error password couldn't be verified");
			}else
				if(reissueResultType.getResultMinor().equals(XKMSConstants.RESULTMINOR_REFUSED)){
					getPrintStream().println("The user doesn't seem to have the wrong status.");
				}else{
					getPrintStream().println("Error occured during processing : " + reissueResultType.getResultMinor());
				}
	}


	
	/**
	 * Returns the encoding that the data should be written in
	 * @return
	 */
	private String useEncoding(String arg){
		
		if(arg.equalsIgnoreCase(ENCODING_P12)){
			return ENCODING_P12;
		}
		
		if(arg.equalsIgnoreCase(ENCODING_JKS)){
			return ENCODING_JKS;
		}
		
		getPrintStream().println("Illegal encoding (should be p12 or jks) : " + arg);
        usage();
    	System.exit(-1); // NOPMD, it's not a JEE app
    	return null;
	}


	
	protected void usage() {
		getPrintStream().println("Command used to reissue an existing certificate");
		getPrintStream().println("Usage : reissue <keystore> <alias> <keypass> <authenticationpassword> <p12|jks> <outputpath (optional)> \n\n");
		getPrintStream().println("Keystore is the p12 or jks about to be renewed.\n");
		getPrintStream().println("alias of the key in the keystore (use 'NOALIAS' for p12).\n");
		getPrintStream().println("keypass is the password to unlock the keystore.\n");
		getPrintStream().println("authenticationpassword is the password used to authenticate against the XKMS service.\n");
        getPrintStream().println("Use p12 or jks for encoding of the generated keystore.\n");
        getPrintStream().println("Outputpath specifies to which directory to write the new keystore to, current directory is used if omitted\n\n");
        getPrintStream().println("Example: reissue oldkey.p12 NOALIAS foo123 xkmspassword  p12");
        getPrintStream().println("Generates a new keystore using the keys in the oldkey.p12");
        
            	        
	}


}

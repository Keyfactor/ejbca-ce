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

import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import javax.xml.bind.JAXBElement;

import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CertTools;
import org.ejbca.core.protocol.xkms.common.XKMSConstants;
import org.ejbca.core.protocol.xkms.common.XKMSUtil;
import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.ejbca.ui.cli.IAdminCommand;
import org.ejbca.ui.cli.IllegalAdminCommandException;
import org.w3._2000._09.xmldsig_.KeyInfoType;
import org.w3._2000._09.xmldsig_.RSAKeyValueType;
import org.w3._2002._03.xkms_.KeyBindingType;
import org.w3._2002._03.xkms_.ObjectFactory;
import org.w3._2002._03.xkms_.PrototypeKeyBindingType;
import org.w3._2002._03.xkms_.RegisterRequestType;
import org.w3._2002._03.xkms_.RegisterResultType;
import org.w3._2002._03.xkms_.UseKeyWithType;





/**
 * Performes KRSS registre calls to an web service.
 *
 * @version $Id$
 * @author Philip Vendil
 */
public class RegisterCommand extends XKMSCLIBaseCommand implements IAdminCommand{

	private ObjectFactory xKMSObjectFactory = new ObjectFactory();
	private org.w3._2000._09.xmldsig_.ObjectFactory sigFactory = new org.w3._2000._09.xmldsig_.ObjectFactory();
	
	private static final int ARG_DN                 = 1;
	private static final int ARG_PASSWORD           = 2;
	private static final int ARG_REVOCATIONCODEID   = 3;
	private static final int ARG_KEYSIZE            = 4;
	private static final int ARG_ENCODING           = 5;
	private static final int ARG_OUTPUTPATH         = 6;
	    
    public RegisterCommand(String[] args) {
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
            
            String subjectDN = args[ARG_DN];
            String password = args[ARG_PASSWORD];
            
            String revocationCodeId = args[ARG_REVOCATIONCODEID];
                        
            String encoding = useEncoding(args[ARG_ENCODING]);
            
            int keySize = getKeySize(args[ARG_KEYSIZE]);
            
            
            String outputPath = "";
            if(args.length >= ARG_OUTPUTPATH +1){
            	if(args[ARG_OUTPUTPATH] != null){
            	  outputPath = args[ARG_OUTPUTPATH] + "/";            	            	
            	}
            }

            KeyPair genKeys = null;
            if(keySize != 0){
              genKeys = KeyTools.genKeys(Integer.toString(keySize), "RSA");
            }
            
            String keyBindingId = genId();            
            PrototypeKeyBindingType prototypeKeyBinding = xKMSObjectFactory.createPrototypeKeyBindingType();
            prototypeKeyBinding.setId(keyBindingId);
            UseKeyWithType useKeyWithType = xKMSObjectFactory.createUseKeyWithType();
            useKeyWithType.setApplication(XKMSConstants.USEKEYWITH_PKIX);
            useKeyWithType.setIdentifier(subjectDN);            
            prototypeKeyBinding.getUseKeyWith().add(useKeyWithType);
            
            if(revocationCodeId != null && !revocationCodeId.equalsIgnoreCase("NULL")){
                byte[] first = XKMSUtil.getSecretKeyFromPassphrase(revocationCodeId, true,20, XKMSUtil.KEY_REVOCATIONCODEIDENTIFIER_PASS1).getEncoded();
                byte[] second = XKMSUtil.getSecretKeyFromPassphrase(new String(first,"ISO8859-1"), false,20, XKMSUtil.KEY_REVOCATIONCODEIDENTIFIER_PASS2).getEncoded();
                prototypeKeyBinding.setRevocationCodeIdentifier(second);
            }
            
            String reqId = genId();
            RegisterRequestType registerRequestType = xKMSObjectFactory.createRegisterRequestType();
            registerRequestType.setId(reqId);
            registerRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CHAIN);
            if(keySize == 0){
              registerRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_PRIVATEKEY);
            }
            registerRequestType.setPrototypeKeyBinding(prototypeKeyBinding);
            
            RegisterResultType registerResultType = null;
            if(genKeys == null){
            	registerResultType = getXKMSInvoker().register(registerRequestType, clientCert, privateKey, password, null, keyBindingId);
            }else{
            	KeyInfoType keyInfoType = sigFactory.createKeyInfoType();
                RSAKeyValueType rsaKeyValueType = sigFactory.createRSAKeyValueType();
                rsaKeyValueType.setExponent(((RSAPublicKey) genKeys.getPublic()).getPublicExponent().toByteArray());
                rsaKeyValueType.setModulus(((RSAPublicKey) genKeys.getPublic()).getModulus().toByteArray());
                JAXBElement<RSAKeyValueType> rsaKeyValue = sigFactory.createRSAKeyValue(rsaKeyValueType);
                keyInfoType.getContent().add(rsaKeyValue);
                
                prototypeKeyBinding.setKeyInfo(keyInfoType);
            	
            	registerResultType = getXKMSInvoker().register(registerRequestType, clientCert, privateKey, password, genKeys.getPrivate(), keyBindingId);            	
            }
            
            if(registerResultType.getResultMajor().equals(XKMSConstants.RESULTMAJOR_SUCCESS) && 
               registerResultType.getResultMinor() == null){
            
                if(registerResultType.getKeyBinding().size() >0){
                	KeyBindingType keyBinding = registerResultType.getKeyBinding().get(0);                	
                	List<X509Certificate> certs = getCertsFromKeyBinding(keyBinding);
                	  
                	X509Certificate userCert = getUserCert(certs);                	
                	certs.remove(userCert);
                	
                	if(registerResultType.getPrivateKey() != null){
                		PrivateKey serverKey = XKMSUtil.getPrivateKeyFromEncryptedXML(registerResultType.getPrivateKey(), password);
                		createKeyStore(userCert, certs, serverKey,password,encoding,outputPath);
                	}else{
                		createKeyStore(userCert, certs,genKeys.getPrivate(),password,encoding,outputPath);
                	}

                }
   
            }else{
            	displayRequestErrors(registerResultType);
            }
    
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
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
        	caChain[i] = (Certificate) caCerts.get(i);
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

	private void displayRequestErrors(RegisterResultType registerResultType) {
		if(registerResultType.getResultMinor().equals(XKMSConstants.RESULTMINOR_NOMATCH)){
			getPrintStream().println("Error no user with given subjectDN could be found");
		}else
			if(registerResultType.getResultMinor().equals(XKMSConstants.RESULTMINOR_NOAUTHENTICATION)){
				getPrintStream().println("Error password couldn't be verified");
			}else
				if(registerResultType.getResultMinor().equals(XKMSConstants.RESULTMINOR_REFUSED)){
					getPrintStream().println("The user doesn't seem to have the right status.");
				}else{
					getPrintStream().println("Error occured during processing : " + registerResultType.getResultMinor());
				}
	}

	private int getKeySize(String keySize) {
		int retval =0;
		try{
		   if(!keySize.equalsIgnoreCase("NOGEN")){
             retval = Integer.parseInt(keySize);
             
             if(retval != 512 && retval != 1024 && retval != 2048 && retval != 4096){
     			getPrintStream().println("Illegal keysize : should be a number of 512, 1024, 2048, 4096 or 'NOGEN': " + keySize);
    			usage();
    			System.exit(-1); // NOPMD, it's not a JEE app   
             }
		   }
		   
		   
		}catch(NumberFormatException e){
			getPrintStream().println("Illegal keysize : should be a number or 'NOGEN': " + keySize);
			usage();
			System.exit(-1); // NOPMD, it's not a JEE app    	
		}
		return retval;
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
    	System.exit(-1); // NOPMD, it's not a JEE app
    	return null;
	}


	
	protected void usage() {
		getPrintStream().println("Command used to register for a certificate");
		getPrintStream().println("Usage : register <subjectDN> <password> <revocationCodeIdentifier> <keySize> <pem|p12|jks> <outputpath (optional)> \n\n");
		getPrintStream().println("The revocationCodeIdentifier is a passphrase or 'NULL' if it isn't used.\n");
		getPrintStream().println("keySize of the generated RSA keys, are only used for client generated keys, use 'NOGEN' othervise.\n");
        getPrintStream().println("Use pem, p12 or jks for encoding of the generated keystore.\n");
        getPrintStream().println("Outputpath specifies to which directory to write the keystore to, current directory is used if omitted\n\n");
        getPrintStream().println("Example: register \"CN=Test Testarson,O=someorg\" \"foo123\" \"My passphrase\" 2048 pem");
        getPrintStream().println("Issues a certificate to  to \"CN=Test Testarson,O=someorg\" and writes it in PEM encoding in the current directory");
        
            	        
	}


}

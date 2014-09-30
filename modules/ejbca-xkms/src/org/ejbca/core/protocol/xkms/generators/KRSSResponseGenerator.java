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

package org.ejbca.core.protocol.xkms.generators;

import gnu.inet.encoding.StringprepException;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import javax.crypto.SecretKey;
import javax.xml.bind.JAXBElement;

import org.apache.log4j.Logger;
import org.apache.xml.security.encryption.XMLEncryptionException;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.XMLSignatureException;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.CesecoreException;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSession;
import org.cesecore.certificates.certificate.CertificateStoreSession;
import org.cesecore.certificates.crl.CrlStoreSession;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CertTools;
import org.ejbca.config.Configuration;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.ejb.ca.auth.EndEntityAuthenticationSession;
import org.ejbca.core.ejb.ca.sign.SignSession;
import org.ejbca.core.ejb.config.GlobalConfigurationSession;
import org.ejbca.core.ejb.keyrecovery.KeyRecoverySession;
import org.ejbca.core.ejb.ra.EndEntityAccessSession;
import org.ejbca.core.ejb.ra.EndEntityManagementSession;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSession;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.keyrecovery.KeyRecoveryInformation;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.protocol.xkms.common.XKMSConstants;
import org.ejbca.core.protocol.xkms.common.XKMSUtil;
import org.w3._2000._09.xmldsig_.RSAKeyValueType;
import org.w3._2000._09.xmldsig_.X509DataType;
import org.w3._2002._03.xkms_.NotBoundAuthenticationType;
import org.w3._2002._03.xkms_.RegisterRequestType;
import org.w3._2002._03.xkms_.RequestAbstractType;
import org.w3._2002._03.xkms_.ResultType;
import org.w3._2002._03.xkms_.RevokeRequestType;
import org.w3._2002._03.xkms_.UseKeyWithType;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * Class generating a common response for register, reissue and recover calls
 *
 * @version $Id$
 */

public class KRSSResponseGenerator extends
		RequestAbstractTypeResponseGenerator {
	
	 private static Logger log = Logger.getLogger(KRSSResponseGenerator.class);
	
	 private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();
	 
	 protected Document requestDoc = null;

	 private CaSession casession;
	 private EndEntityAuthenticationSession authenticationSession;
	 private CertificateStoreSession certificateStoreSession;
	 private EndEntityAccessSession endEntityAccessSession;
	 private EndEntityProfileSession endEntityProfileSession;
	 private KeyRecoverySession keyRecoverySession;
	 private GlobalConfigurationSession globalConfigurationSession;
	 private SignSession signSession;
	 private EndEntityManagementSession endEntityManagementSession;
	 
    public KRSSResponseGenerator(String remoteIP, RequestAbstractType req, Document requestDoc,
    		CaSession casession, EndEntityAuthenticationSession authenticationSession, CertificateStoreSession certificateStoreSession, EndEntityAccessSession endEntityAccessSession,
    		EndEntityProfileSession endEntityProfileSession, KeyRecoverySession keyRecoverySession, GlobalConfigurationSession globalConfigurationSession,
    		SignSession signSession, EndEntityManagementSession endEntityManagementSession, CrlStoreSession crlSession) {
        super(remoteIP, req, casession, certificateStoreSession, crlSession);
        this.requestDoc = requestDoc;
        this.casession = casession;
        this.authenticationSession = authenticationSession;
        this.certificateStoreSession = certificateStoreSession;
        this.endEntityAccessSession = endEntityAccessSession;
        this.endEntityProfileSession = endEntityProfileSession;
        this.keyRecoverySession = keyRecoverySession;
        this.globalConfigurationSession = globalConfigurationSession;
        this.signSession = signSession;
        this.endEntityManagementSession = endEntityManagementSession;
    }
	
	/**
	 * Method extracting the public key from the message.
	 * @param req the request
	 * @return the public key as and PublicKey or Certificate or null if no public key could be found.
	 */
	protected Object getPublicKeyInfo(RequestAbstractType req, boolean registerRequest){
		Object retval = null;
	
		if(GeneralizedKRSSMessageHelper.getKeyBindingAbstractType(req).getKeyInfo() != null && GeneralizedKRSSMessageHelper.getKeyBindingAbstractType(req).getKeyInfo().getContent().get(0) != null){
			try{
				@SuppressWarnings("unchecked")
                JAXBElement<Object> element = (JAXBElement<Object>) GeneralizedKRSSMessageHelper.getKeyBindingAbstractType(req).getKeyInfo().getContent().get(0);
				if(element.getValue() instanceof RSAKeyValueType && registerRequest){
					@SuppressWarnings("unchecked")
                    RSAKeyValueType rSAKeyValueType  = ((JAXBElement<RSAKeyValueType>) GeneralizedKRSSMessageHelper.getKeyBindingAbstractType(req).getKeyInfo().getContent().get(0)).getValue();        
					RSAPublicKeySpec rSAPublicKeySpec = new RSAPublicKeySpec(new BigInteger(rSAKeyValueType.getModulus()), new BigInteger(rSAKeyValueType.getExponent()));        
					retval= KeyFactory.getInstance("RSA").generatePublic(rSAPublicKeySpec);
				}
				if(element.getValue() instanceof X509DataType){
					Iterator<Object> iter = ((X509DataType) element.getValue()).getX509IssuerSerialOrX509SKIOrX509SubjectName().iterator();
					while(iter.hasNext()){
						@SuppressWarnings("unchecked")
                        JAXBElement<byte[]> next = (JAXBElement<byte[]>) iter.next();					
						if(next.getName().getLocalPart().equals("X509Certificate")){
							byte[] encoded = next.getValue();

							try {
								X509Certificate nextCert = (X509Certificate)CertTools.getCertfromByteArray(encoded);
								if(nextCert.getBasicConstraints() == -1){
									retval = nextCert;
								}
							} catch (CertificateException e) {
								log.error(intres.getLocalizedMessage("xkms.errordecodingcert"),e);								
								resultMajor = XKMSConstants.RESULTMAJOR_RECIEVER;
								resultMinor = XKMSConstants.RESULTMINOR_FAILURE;
							}

						}else{
							resultMajor = XKMSConstants.RESULTMAJOR_SENDER;
							resultMinor = XKMSConstants.RESULTMINOR_MESSAGENOTSUPPORTED;
						}
					}
				}
			
				if(retval == null){
					resultMajor = XKMSConstants.RESULTMAJOR_SENDER;
					resultMinor = XKMSConstants.RESULTMINOR_MESSAGENOTSUPPORTED;
				}
				
			} catch (InvalidKeySpecException e) {
				log.error(e);
				resultMajor = XKMSConstants.RESULTMAJOR_SENDER;
				resultMinor = XKMSConstants.RESULTMINOR_MESSAGENOTSUPPORTED;
			} catch (NoSuchAlgorithmException e) {
				log.error(e);
				resultMajor = XKMSConstants.RESULTMAJOR_SENDER;
				resultMinor = XKMSConstants.RESULTMINOR_MESSAGENOTSUPPORTED;
			}
		}
		
		
		
		return retval;
	}
	
	/**
     * Method performing the actual certificate generation, from the subjectDN and password
     * @param revocationCode The code used later by the user to revoke, it it is allowed by the XKMS Service
     * @return the generated certificate or null if generation failed
     */
    protected X509Certificate registerReissueOrRecover(boolean recover, boolean reissue, ResultType response, EndEntityInformation endEntityInformation, String password,  
    		                                  PublicKey publicKey, String revocationCode) {
		X509Certificate retval = null;
    	
		// Check the status of the user
		if((!recover && endEntityInformation.getStatus() == EndEntityConstants.STATUS_NEW) || (recover && endEntityInformation.getStatus() == EndEntityConstants.STATUS_KEYRECOVERY)){
				
			try{		
				boolean usekeyrecovery = !reissue && ((GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(Configuration.GlobalConfigID)).getEnableKeyRecovery();

				boolean savekeys = endEntityInformation.getKeyRecoverable() && usekeyrecovery &&  (endEntityInformation.getStatus() != EndEntityConstants.STATUS_KEYRECOVERY);
				boolean loadkeys = (endEntityInformation.getStatus() == EndEntityConstants.STATUS_KEYRECOVERY) && usekeyrecovery;

				// get users Token Type.
				int tokentype = endEntityInformation.getTokenType();

				PublicKey certKey = null;
				PrivateKey privKey = null;
				KeyPair keyPair = null;
				KeyRecoveryInformation keyData = null;
				boolean reusecertificate = false;
				if(loadkeys){
					EndEntityProfile endEntityProfile = endEntityProfileSession.getEndEntityProfile(endEntityInformation.getEndEntityProfileId());
					reusecertificate = endEntityProfile.getReUseKeyRecoveredCertificate();

					// used saved keys.
					keyData = keyRecoverySession.recoverKeys(pubAdmin, endEntityInformation.getUsername(), endEntityInformation.getEndEntityProfileId());
					keyPair = keyData.getKeyPair();
					certKey = keyPair.getPublic();
					privKey = keyPair.getPrivate();

					if(reusecertificate){
					    keyRecoverySession.unmarkUser(pubAdmin,endEntityInformation.getUsername());
					}
				}
				else{
					// generate new keys.
					if(!reissue && (tokentype == SecConst.TOKEN_SOFT_P12 || tokentype == SecConst.TOKEN_SOFT_JKS || tokentype == SecConst.TOKEN_SOFT_PEM)){
						keyPair = KeyTools.genKeys(Integer.toString(XKMSConfig.getServerKeyLength()), "RSA");
						certKey = keyPair.getPublic();
						privKey = keyPair.getPrivate();
					}
					if(reissue || tokentype == SecConst.TOKEN_SOFT_BROWSERGEN){
						certKey = publicKey;
					}
				}

				X509Certificate cert = null;
				if(reusecertificate){
					cert = (X509Certificate) keyData.getCertificate();	             
					boolean finishUser = casession.getCAInfo(pubAdmin,CertTools.getIssuerDN(cert).hashCode()).getFinishUser();
					if(finishUser){	           	  
					    authenticationSession.finishUser(endEntityInformation);
					}

				}else{        	 
					cert = (X509Certificate) signSession.createCertificate(pubAdmin, endEntityInformation.getUsername(), password, certKey);	 
				}

				if (savekeys) {
					// Save generated keys to database.	             
				    keyRecoverySession.addKeyRecoveryData(pubAdmin, cert, endEntityInformation.getUsername(), keyPair);
				}

				// Save the revocation code
				if(revocationCode != null && !recover){
					EndEntityInformation data = endEntityAccessSession.findUser(pubAdmin, endEntityInformation.getUsername());
					ExtendedInformation ei = data.getExtendedinformation();
					if (ei == null) {
						ei = new ExtendedInformation();
					}
					ei.setRevocationCodeIdentifier(revocationCode);
					data.setExtendedinformation(ei);
					endEntityManagementSession.changeUser(raAdmin, data, true);

				}

				if(privKey != null){
					GeneralizedKRSSMessageHelper.setPrivateKey(response, XKMSUtil.getEncryptedXMLFromPrivateKey((RSAPrivateCrtKey) privKey, password));
				}

				retval = cert;
			} catch (CesecoreException e) {
			    // CesecoreExceptions are handled
				log.info(intres.getLocalizedMessage("xkms.errorregisteringreq")+": "+e.getMessage());				
            } catch (Exception e) {
                // Unexpected error?
                log.error(intres.getLocalizedMessage("xkms.errorregisteringreq"),e);             
            } 

			if(retval == null){
				resultMajor = XKMSConstants.RESULTMAJOR_RECIEVER;
				resultMinor = XKMSConstants.RESULTMINOR_FAILURE;
			}
			
		}else{
			log.info(intres.getLocalizedMessage("xkms.errorinreqwrongstatus",Integer.valueOf(endEntityInformation.getStatus()),endEntityInformation.getUsername()));			
			resultMajor = XKMSConstants.RESULTMAJOR_SENDER;
			resultMinor = XKMSConstants.RESULTMINOR_REFUSED;
		}
    	

		
		return retval;
	}
	
	protected boolean confirmPOP(PublicKey publicKey) {
    	boolean retval = false;
    	 // Check that POP is required
    	if(XKMSConfig.isPOPRequired() && publicKey != null){
    		// Get the public key 
    		try{
              
    			org.w3c.dom.NodeList pOPElements = requestDoc.getElementsByTagNameNS("http://www.w3.org/2002/03/xkms#", "ProofOfPossession");
    			if(pOPElements.getLength() == 1){
    				Element pOPe = (Element) pOPElements.item(0);
    				org.w3c.dom.NodeList popVerXmlSigs = pOPe.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature");
    				org.w3c.dom.Element popVerXmlSigElement = (org.w3c.dom.Element)popVerXmlSigs.item(0);        
    				org.apache.xml.security.signature.XMLSignature popVerXmlSig = new org.apache.xml.security.signature.XMLSignature(popVerXmlSigElement, null);
    				if(popVerXmlSig.checkSignatureValue(publicKey)){
    					retval = true;
    				}
    			}
    			
    			if(!retval){
    				resultMajor = XKMSConstants.RESULTMAJOR_SENDER;
    				resultMinor = XKMSConstants.RESULTMINOR_POPREQUIRED;    				  
    			} 
    		}catch(XMLSignatureException e){
    			log.error(e);
    			resultMajor = XKMSConstants.RESULTMAJOR_SENDER;
    			resultMinor = XKMSConstants.RESULTMINOR_POPREQUIRED;
    		} catch (XMLSecurityException e) {
    			log.error(e);
    			resultMajor = XKMSConstants.RESULTMAJOR_SENDER;
    			resultMinor = XKMSConstants.RESULTMINOR_POPREQUIRED;
    		}
	
    	}else{
    		retval = true;
    	}
    		
		return retval;
	}

	protected boolean isPasswordEncrypted(RequestAbstractType req) {
        if(GeneralizedKRSSMessageHelper.getAuthenticationType(req) == null){
        	return false;
        }
		return GeneralizedKRSSMessageHelper.getAuthenticationType(req).getKeyBindingAuthentication() != null;
	}
	
	protected List<EndEntityInformation> findUserData(String subjectDN) {
		List<EndEntityInformation> retval = new ArrayList<EndEntityInformation>();
		
		if(subjectDN != null){
			try {
				retval.addAll(endEntityAccessSession.findUserBySubjectDN(pubAdmin, subjectDN));
			} catch (AuthorizationDeniedException e) {
				log.error(intres.getLocalizedMessage("xkms.errorinprivs"),e);				
			}		
			if(retval.size() == 0){
				resultMajor = XKMSConstants.RESULTMAJOR_SENDER;
				resultMinor = XKMSConstants.RESULTMINOR_NOMATCH;
			}
		}
		return retval;
	}
	
	/**
	 * Method finding the userdata of the specified cert or null
	 * if the user couldn't be foundl
	 */
	protected EndEntityInformation findUserData(X509Certificate cert) {
		EndEntityInformation retval = null;
		try {
			String username = certificateStoreSession.findUsernameByCertSerno(cert.getSerialNumber(), CertTools.getIssuerDN(cert));
			if (log.isDebugEnabled()) {
				log.debug("Username for certificate with issuerDN:"+CertTools.getIssuerDN(cert)+", serialNo:"+CertTools.getSerialNumber(cert)+" :"+username);
			}
			retval = endEntityAccessSession.findUser(pubAdmin, username);
			if(retval==null){
				if (log.isDebugEnabled()) {
					log.debug("User with username "+username+"not found.");
				}
			}
		} catch (Exception e) {
			log.error(intres.getLocalizedMessage("xkms.errorfindinguserdata",cert.getSubjectDN().toString()));			
		}
		if(retval==null){
			if (log.isDebugEnabled()) {
				log.debug("No user for certificate with issuerDN:"+CertTools.getIssuerDN(cert)+", serialNo:"+CertTools.getSerialNumber(cert));
			}
			resultMajor = XKMSConstants.RESULTMAJOR_SENDER;
			resultMinor = XKMSConstants.RESULTMINOR_NOMATCH;
		}

		return retval;
	}
	
	/**
     * Method that extracts and verifies the password. Then returns the undigested 
     * password from database
     * @param req in Document encoding
     * @param password cleartext version from database
     * @return The password or null if the password doesn't verify
     */
	protected String getEncryptedPassword(Document reqDoc, String password) {
		String retval = null;
		
		try {
			SecretKey sk = XKMSUtil.getSecretKeyFromPassphrase(password, true, 20, XKMSUtil.KEY_AUTHENTICATION);
			org.w3c.dom.NodeList authenticationElements = reqDoc.getElementsByTagNameNS("http://www.w3.org/2002/03/xkms#", "Authentication");        
			Element ae = (Element) authenticationElements.item(0);        
			org.w3c.dom.NodeList xmlSigs = ae.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature");

			org.w3c.dom.Element xmlSigElement = (org.w3c.dom.Element)xmlSigs.item(0);        
			org.apache.xml.security.signature.XMLSignature xmlVerifySig = new org.apache.xml.security.signature.XMLSignature(xmlSigElement, null);

			if(xmlVerifySig.checkSignatureValue(sk)){
				retval = password;
			}else{
				resultMajor = XKMSConstants.RESULTMAJOR_SENDER;
				resultMinor = XKMSConstants.RESULTMINOR_NOAUTHENTICATION;	
			}
		} catch (Exception e) {
			log.error(intres.getLocalizedMessage("xkms.errorauthverification"),e);			
			resultMajor = XKMSConstants.RESULTMAJOR_SENDER;
			resultMinor = XKMSConstants.RESULTMINOR_NOAUTHENTICATION;
		} 

		return retval;
	}

	/**
	 * Returns the password when having NotBoundAuthentication instead
	 * of KeyBindingAuthentication. 
	 * 
	 * @param req
	 * @return The password or null if no NotBoundAuthentication were found.
	 */
    protected String getClearPassword(RequestAbstractType req, String dBPassword) {
		String retval = null;
		NotBoundAuthenticationType notBoundAuthenticationType = GeneralizedKRSSMessageHelper.getAuthenticationType(req).getNotBoundAuthentication(); 
		if(notBoundAuthenticationType != null){
			retval = new String(notBoundAuthenticationType.getValue());
		}else{
			resultMajor = XKMSConstants.RESULTMAJOR_SENDER;
			resultMinor = XKMSConstants.RESULTMINOR_MESSAGENOTSUPPORTED;
		}
		
		if(!retval.equals(dBPassword)){
			resultMajor = XKMSConstants.RESULTMAJOR_SENDER;
			resultMinor = XKMSConstants.RESULTMINOR_NOAUTHENTICATION;
			retval = null;
		}
				
		return retval;
	}
	
	/**
	 * Method that returns the subject DN taken from a UseKeyWith PKIX tag
	 * If no such tag exist is null returned and errorcodes set.
	 * @param req
	 * @return the subjectDN of null
	 */
    protected String getSubjectDN(RequestAbstractType req) {
	    String retval = null;
		
	    for(UseKeyWithType next : GeneralizedKRSSMessageHelper.getKeyBindingAbstractType(req).getUseKeyWith()){
	    	if(next.getApplication().equals(XKMSConstants.USEKEYWITH_PKIX)){
	    		retval = CertTools.stringToBCDNString(next.getIdentifier());
	    		break;
	    	}
	    }
	    
	    if(retval == null){
	    	resultMajor = XKMSConstants.RESULTMAJOR_SENDER;
	    	resultMinor = XKMSConstants.RESULTMINOR_MESSAGENOTSUPPORTED;
	    }
	    
		return retval;
	}
	
	protected boolean certIsValid(X509Certificate cert) {
		boolean retval = false;
		
		try {
		    CAInfo cAInfo = casession.getCAInfo(pubAdmin, CertTools.getIssuerDN(cert).hashCode());
		    Collection<Certificate> caCertChain = cAInfo.getCertificateChain();
		    Iterator<Certificate> iter = caCertChain.iterator();

		    boolean revoked = false;				
		    if (certificateStoreSession.isRevoked(CertTools.getIssuerDN(cert), cert.getSerialNumber())) {
		        revoked = true;
		    }

		    while(iter.hasNext()){
		        X509Certificate cACert = (X509Certificate) iter.next();
		        if (certificateStoreSession.isRevoked(CertTools.getIssuerDN(cACert), cACert.getSerialNumber())) {
		            revoked = true;
		        }
		    }

		    if(!revoked){
		        retval = verifyCert(caCertChain, cert);
		    }
		} catch (CADoesntExistsException e) {
            log.info("CA with id "+CertTools.getIssuerDN(cert).hashCode()+" does not exist");
		} catch (Exception e) {
			log.error("Exception during certificate validation: ", e);
		}
		
		if(retval == false){
			resultMajor = XKMSConstants.RESULTMAJOR_SENDER;
			resultMinor = XKMSConstants.RESULTMINOR_REFUSED;
		}

		return retval;
	}


    /**
     * method that verifies the certificate and returns an error message
     * @param cACertChain
     * @param trustedCRLs
     * @param cert
     * @return  true if everything is OK
     */
    private boolean verifyCert(Collection<Certificate> cACertChain, X509Certificate usercert) {

        boolean retval = false;

        try {
            X509Certificate rootCert = null;
            Iterator<Certificate> iter = cACertChain.iterator();
            while (iter.hasNext()) {
                X509Certificate cert = (X509Certificate) iter.next();
                if (cert.getIssuerDN().equals(cert.getSubjectDN())) {
                    rootCert = cert;
                    break;
                }
            }

            if (rootCert == null) {
                throw new CertPathValidatorException("Error Root CA cert not found in cACertChain");
            }

            List<Certificate> list = new ArrayList<Certificate>();
            list.add(usercert);
            list.addAll(cACertChain);

            CollectionCertStoreParameters ccsp = new CollectionCertStoreParameters(list);
            CertStore store = CertStore.getInstance("Collection", ccsp);

            //validating path
            List<Certificate> certchain = new ArrayList<Certificate>();
            certchain.addAll(cACertChain);
            certchain.add(usercert);
            CertPath cp = CertificateFactory.getInstance("X.509", "BC").generateCertPath(certchain);

            Set<TrustAnchor> trust = new HashSet<TrustAnchor>();
            trust.add(new TrustAnchor(rootCert, null));

            CertPathValidator cpv = CertPathValidator.getInstance("PKIX", "BC");
            PKIXParameters param = new PKIXParameters(trust);
            param.addCertStore(store);
            param.setDate(new Date());
            param.setRevocationEnabled(false);

            cpv.validate(cp, param);
            retval = true;
        } catch (Exception e) {
            log.error(intres.getLocalizedMessage("xkms.errorverifyingcert"), e);
        }
        return retval;
    }
    
	/**
	 * Method that checks that the given respondWith specification is valid.
	 * I.e contains one supported RespondWith tag.
	 */
	public boolean checkValidRespondWithRequest(List<String> respondWithList, boolean revokeCall){
		boolean returnval = false;
		if(revokeCall){
			returnval = true;
		}
		
		String[] supportedRespondWith = {XKMSConstants.RESPONDWITH_X509CERT,
				                         XKMSConstants.RESPONDWITH_X509CHAIN,
				                         XKMSConstants.RESPONDWITH_X509CRL,
				                         XKMSConstants.RESPONDWITH_PRIVATEKEY};		
	     
		for(int i=0;i<supportedRespondWith.length;i++){
		  returnval |= respondWithList.contains(supportedRespondWith[i]); 
		  if(returnval){
			  break;
		  }
		}
		  		
		return returnval;
	}
	
	/**
	 * Method returning the revocation code identifier or null
	 * if it does not exist.
	 * 
	 * @param req
	 * @return the RevocationCode or null if it doesn't exist.
	 */
    protected String getRevocationCode(RequestAbstractType req) {
    	String retval = null;
    	
    	if(req instanceof RegisterRequestType){
    		if(((RegisterRequestType) req).getPrototypeKeyBinding().getRevocationCodeIdentifier() != null){
    			retval = new String(Hex.encode(((RegisterRequestType) req).getPrototypeKeyBinding().getRevocationCodeIdentifier()));
    		}
    	}
    	if(req instanceof RevokeRequestType){
    		byte[] unMACedCode= ((RevokeRequestType) req).getRevocationCode();
    		if(unMACedCode != null){
    			try{
    				retval = new String(Hex.encode(XKMSUtil.getSecretKeyFromPassphrase(new String(unMACedCode,"ISO8859-1"), false, 20, XKMSUtil.KEY_REVOCATIONCODEIDENTIFIER_PASS2).getEncoded()));
    			}catch (XMLEncryptionException e) {
    				log.error(e);
    			} catch (StringprepException e) {// is never thrown}
    			} catch (UnsupportedEncodingException e) {
    				log.error(e);
				}
    		}
    	}
		
		return retval;
	}
}

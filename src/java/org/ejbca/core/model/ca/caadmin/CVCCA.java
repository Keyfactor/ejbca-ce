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

package org.ejbca.core.model.ca.caadmin;

import java.io.IOException;
import java.io.Serializable;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ca.SignRequestSignatureException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceInfo;
import org.ejbca.core.model.ca.catoken.CATokenOfflineException;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfile;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.cvc.AuthorizationRoleEnum;
import org.ejbca.cvc.CAReferenceField;
import org.ejbca.cvc.CVCertificate;
import org.ejbca.cvc.CardVerifiableCertificate;
import org.ejbca.cvc.CertificateGenerator;
import org.ejbca.cvc.HolderReferenceField;
import org.ejbca.cvc.exception.ConstructionException;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;




/**
 * CVCCA is a implementation of a CA and holds data specific for Certificate and CRL generation 
 * according to the CVC (Card Verifiable Certificate) standard used in EU EAC electronic passports.  
 *
 * @version $Id$
 */
public class CVCCA extends CA implements Serializable {

	private static final long serialVersionUID = 1L;

	private static final Logger log = Logger.getLogger(CVCCA.class);

	/** Internal localization of logs and errors */
	private static final InternalResources intres = InternalResources.getInstance();

	/** Version of this class, if this is increased the upgrade() method will be called automatically */
	public static final float LATEST_VERSION = 1;


	// Public Methods
	/** Creates a new instance of CA, this constructor should be used when a new CA is created */
	public CVCCA(CVCCAInfo cainfo) {
		super(cainfo);  

		setFinishUser(cainfo.getFinishUser());
		setIncludeInHealthCheck(cainfo.getIncludeInHealthCheck());

		data.put(CA.CATYPE, new Integer(CAInfo.CATYPE_CVC));
		data.put(VERSION, new Float(LATEST_VERSION));   
	}

	/** Constructor used when retrieving existing CVCCA from database. 
	 * @throws IllegalKeyStoreException */
	public CVCCA(HashMap data, int caId, String subjectDN, String name, int status, Date updateTime) throws IllegalKeyStoreException{
		super(data);
		ArrayList externalcaserviceinfos = new ArrayList();
		Iterator iter = getExternalCAServiceTypes().iterator(); 	
		while(iter.hasNext()){
			ExtendedCAServiceInfo info = this.getExtendedCAServiceInfo(((Integer) iter.next()).intValue());
			if (info != null) {
				externalcaserviceinfos.add(info);  	    			
			}
		}
		CAInfo info = new CVCCAInfo(subjectDN, name, status, updateTime, getCertificateProfileId(),  
				getValidity(), getExpireTime(), getCAType(), getSignedBy(), getCertificateChain(),
				getCAToken(caId).getCATokenInfo(), getDescription(), getRevokationReason(), getRevokationDate(), getCRLPeriod(), getCRLIssueInterval(), getCRLOverlapTime(), getDeltaCRLPeriod(), 
				getCRLPublishers(), getFinishUser(), externalcaserviceinfos, 
				getApprovalSettings(), getNumOfRequiredApprovals(),
				getIncludeInHealthCheck());
		super.setCAInfo(info);
	}

	public void updateCA(CAInfo cainfo) throws Exception{
		super.updateCA(cainfo); 
	}


	public byte[] createPKCS7(Certificate cert, boolean includeChain) throws SignRequestSignatureException {
		log.info("There is no such thing as a CVC PKCS7");
		return null;
	}    

	/**
	 * @see CA#createRequest(Collection, String)
	 */
	public byte[] createRequest(Collection attributes, String signAlg) throws CATokenOfflineException {

		byte[] ret = null;
		// Create a CVC request. 
		// No outer signature on this self signed request
		KeyPair keyPair;
		try {
			keyPair = new KeyPair(getCAToken().getPublicKey(SecConst.CAKEYPURPOSE_CERTSIGN), getCAToken().getPrivateKey(SecConst.CAKEYPURPOSE_CERTSIGN));
			String subject = getCAInfo().getSubjectDN();
			String country = CertTools.getPartFromDN(subject, "C");
			String mnemonic = CertTools.getPartFromDN(subject, "O");
			String seq = CertTools.getPartFromDN(subject, "CN");
			HolderReferenceField holderRef = new HolderReferenceField(country, mnemonic, seq);
			CAReferenceField caRef = new CAReferenceField(holderRef.getCountry(), holderRef.getMnemonic(), holderRef.getSequence());
			CVCertificate request = CertificateGenerator.createRequest(keyPair, signAlg, caRef, holderRef);
			ret = request.getDEREncoded();
		} catch (IllegalKeyStoreException e) {
            throw new javax.ejb.EJBException(e);
		} catch (InvalidKeyException e) {
            throw new javax.ejb.EJBException(e);
		} catch (NoSuchAlgorithmException e) {
            throw new javax.ejb.EJBException(e);
		} catch (NoSuchProviderException e) {
            throw new javax.ejb.EJBException(e);
		} catch (SignatureException e) {
            throw new javax.ejb.EJBException(e);
		} catch (IOException e) {
            throw new javax.ejb.EJBException(e);
		} catch (ConstructionException e) {
            throw new javax.ejb.EJBException(e);
		}

		return ret;
	}

	public Certificate generateCertificate(UserDataVO subject, 
			PublicKey publicKey, 
			int keyusage, 
			Date notBefore,
			Date notAfter,
			CertificateProfile certProfile,
			X509Extensions extensions) throws Exception{
		log.debug(">generateCertificate("+notBefore+", "+notAfter+")");
		// Get the fields for the Holder Reference fields
		// country is taken from C in a DN string, mnemonic from O in a DN string and seq from CN in a DN string
		String country = CertTools.getPartFromDN(subject.getDN(), "C");
		String mnemonic = CertTools.getPartFromDN(subject.getDN(), "O");
		String seq = CertTools.getPartFromDN(subject.getDN(), "CN");
		// The DN 'CN=00111,O=CVCA-RPS,C=SE' will make the following reference
        //HolderReferenceField holderRef = new HolderReferenceField("SE","CVCA-RPS","00111");		
        HolderReferenceField holderRef = new HolderReferenceField(country, mnemonic, seq);

        // Check if this is a root CA we are creating
        boolean isRootCA = false;
        if (certProfile.getType() == CertificateProfile.TYPE_ROOTCA) {
        	isRootCA = true;
        }
        
        // Get CA reference
        CardVerifiableCertificate cacert = (CardVerifiableCertificate)getCACertificate();
        // Get certificate validity time notBefore and notAfter
        CertificateValidity val = new CertificateValidity(subject, certProfile, notBefore, notAfter, cacert, isRootCA);

        // We must take the issuer DN directly from the CA-certificate, if we are not creating a new Root CA
        CAReferenceField caRef = null;
        AuthorizationRoleEnum authRole = AuthorizationRoleEnum.IS;
        if (isRootCA) {
        	// This will be an initial root CA, since no CA-certificate exists
        	if (log.isDebugEnabled()) {
        		log.debug("Using Holder Ref also as CA Ref, because it is a root CA");
        	}
            caRef = new CAReferenceField(holderRef.getCountry(), holderRef.getMnemonic(), holderRef.getSequence());
            log.debug("Using AuthorizationRoleEnum.CVCA");
            authRole = AuthorizationRoleEnum.CVCA;
        } else {
        	if (log.isDebugEnabled()) {
        		log.debug("Using CA Ref directly from the CA certificates Holder Ref");
        	}
            HolderReferenceField hr = cacert.getCVCertificate().getCertificateBody().getHolderReference();
            caRef = new CAReferenceField(hr.getCountry(), hr.getMnemonic(), hr.getSequence());
            if (certProfile.getType() == CertificateProfile.TYPE_SUBCA) {
            	// If the holder DV's country and the CA's country is the same, this is a domestic DV
            	// If the holder DV's country is something else, it is a foreign DV
            	if (StringUtils.equals(caRef.getCountry(), holderRef.getCountry())) {
                	authRole = AuthorizationRoleEnum.DV_D;            		
                    log.debug("Using AuthorizationRoleEnum.DV_D");
            	} else {
                	authRole = AuthorizationRoleEnum.DV_F;	            		
                    log.debug("Using AuthorizationRoleEnum.DV_F");
            	}
            }
        }

        // Generate the CVC certificate using Keijos library
        String sigAlg = getCAToken().getCATokenInfo().getSignatureAlgorithm();
        CVCertificate cvc = CertificateGenerator.createCertificate(publicKey, getCAToken().getPrivateKey(SecConst.CAKEYPURPOSE_CERTSIGN), 
        		sigAlg, caRef, holderRef, authRole, val.getNotBefore(), val.getNotAfter(), getCAToken().getProvider());

        if (log.isDebugEnabled()) {
            log.debug("Certificate: "+cvc.toString());
            log.debug("Certificate bytes: "+new String(Base64.encode(cvc.getDEREncoded())));        	
        }
        
        CardVerifiableCertificate retCert = new CardVerifiableCertificate(cvc);
        // Verify certificate before returning
        retCert.verify(getCAToken().getPublicKey(SecConst.CAKEYPURPOSE_CERTSIGN));
        
		log.debug("<generateCertificate()");
		return retCert;                                                                                        
	}


	public CRL generateCRL(Collection certs, int crlnumber) 
	throws CATokenOfflineException, IllegalKeyStoreException, IOException, SignatureException, NoSuchProviderException, InvalidKeyException, CRLException, NoSuchAlgorithmException {
        String msg = intres.getLocalizedMessage("signsession.nocrlcreate", "CVC");
        log.info(msg);
		return null;        
	}

	public CRL generateDeltaCRL(Collection certs, int crlnumber, int basecrlnumber)
	throws CATokenOfflineException, IllegalKeyStoreException, IOException, SignatureException, NoSuchProviderException, InvalidKeyException, CRLException, NoSuchAlgorithmException {
        String msg = intres.getLocalizedMessage("signsession.nocrlcreate", "CVC");
        log.info(msg);
		return null;        
	}

	/** Implementation of UpgradableDataHashMap function getLatestVersion */
	public float getLatestVersion(){
		return LATEST_VERSION;
	}

	/** Implementation of UpgradableDataHashMap function upgrade. 
	 */
	public void upgrade(){
		if(Float.compare(LATEST_VERSION, getVersion()) != 0) {
			// New version of the class, upgrade
			log.info("Upgrading CVCCA with version "+getVersion());

			// Put upgrade code here...

			data.put(VERSION, new Float(LATEST_VERSION));
		}  
	}

	/**
	 * Method to upgrade new (or existing external caservices)
	 * This method needs to be called outside the regular upgrade
	 * since the CA isn't instansiated in the regular upgrade.
	 *
	 */
	public boolean upgradeExtendedCAServices() {
		// Nothing to upgrade yet
		return true;
	}


	public byte[] decryptData(byte[] data, int cAKeyPurpose) throws Exception {
		throw new IllegalArgumentException("decryptData not implemented for CVC CA");
	}

	public byte[] encryptData(byte[] data, int keyPurpose) throws Exception {
		throw new IllegalArgumentException("encryptData not implemented for CVC CA");
	}

}

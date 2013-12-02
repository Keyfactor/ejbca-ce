/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/ 
package org.cesecore.certificates.ca;

import java.io.Serializable;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CRLHolder;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceInfo;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceTypes;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.internal.InternalResources;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenOfflineException;


/**
 * CVCCA is a implementation of a CA and holds data specific for Certificate and CRL generation 
 * according to the CVC (Card Verifiable Certificate) standard used in EU EAC electronic passports.  
 *
 * @version $Id$
 */
public class CVCCA extends CA implements Serializable {

	private static final long serialVersionUID = 3L;
	private static final Logger log = Logger.getLogger(CVCCA.class);

	/** Internal localization of logs and errors */
	private static final InternalResources intres = InternalResources.getInstance();

	/** Version of this class, if this is increased the upgrade() method will be called automatically */
	public static final float LATEST_VERSION = 3;

	   /** Definition of the optional database integrity protection implementation */
    private static final String implClassName = "org.cesecore.certificates.ca.CVCCAEACImpl";
    /** Cache class so we don't have to do Class.forName for every entity object created */
    private static volatile Class<?> implClass = null;
    /** Optimization variable so we don't have to check for existence of implClass for every construction of an object */
    private static volatile boolean implExists = true;

	private CVCCAImpl impl;
	
	/** Creates a new instance of CA, this constructor should be used when a new CA is created */
	public CVCCA(CVCCAInfo cainfo) {
	    super(cainfo);
        data.put(CA.CATYPE, Integer.valueOf(CAInfo.CATYPE_CVC));
        data.put(VERSION, new Float(LATEST_VERSION));   
        // Create the implementation
        createCAImpl(cainfo);
	}

    private void createCAImpl(final CVCCAInfo cainfo) {
        // cainfo can be used to differentiate between different types of CVC CA implementations as there
        // can be several different types of CVC, EAC, Tachograph etc.
        if (implExists) {
            try {
                if (implClass == null) {
                    // We only end up here once, if the class does not exist, we will never end up here again (ClassNotFoundException) 
                    // and if the class exists we will never end up here again (it will not be null)
                    implClass = Class.forName(implClassName);
                    log.debug("CVCCAEACImpl is available, and used, in this version of EJBCA.");
                }
                impl = (CVCCAImpl)implClass.newInstance();
                impl.setCA(this);
            } catch (ClassNotFoundException e) {
                // We only end up here once, if the class does not exist, we will never end up here again
                implExists = false;
                log.info("CVC CA is not available in the version of EJBCA.");
                // No implementation found
                throw new RuntimeException("CVC CA is not available in the version of EJBCA.");
            } catch (InstantiationException e) {
                log.error("Error intitilizing CVCCA: ", e);
            } catch (IllegalAccessException e) {
                log.error("Error intitilizing CVCCA protection: ", e);
            }           
        } else {
            // No implementation found
            log.info("CVC CA is not available in the version of EJBCA.");
            throw new RuntimeException("CVC CA is not available in the version of EJBCA.");
        }
    }

	/** Constructor used when retrieving existing CVCCA from database. */
	public CVCCA(HashMap<Object, Object> data, int caId, String subjectDN, String name, int status, Date updateTime) {
		super(data);
		final List<ExtendedCAServiceInfo> externalcaserviceinfos = new ArrayList<ExtendedCAServiceInfo>();
        for (final Integer externalCAServiceType : getExternalCAServiceTypes()) {
            //Type was removed in 6.0.0. It is removed from the database in the upgrade method in this class, but it needs to be ignored 
            //for instantiation. 
            if (externalCAServiceType != ExtendedCAServiceTypes.TYPE_OCSPEXTENDEDSERVICE) {
                final ExtendedCAServiceInfo info = this.getExtendedCAServiceInfo(externalCAServiceType.intValue());
                if (info != null) {
                    externalcaserviceinfos.add(info);
                }
            }
		}
		final CVCCAInfo info = new CVCCAInfo(subjectDN, name, status, updateTime, getCertificateProfileId(),  
				getValidity(), getExpireTime(), getCAType(), getSignedBy(), getCertificateChain(),
				getCAToken(), getDescription(), getRevocationReason(), getRevocationDate(), getCRLPeriod(), getCRLIssueInterval(), getCRLOverlapTime(), getDeltaCRLPeriod(), 
				getCRLPublishers(), getFinishUser(), externalcaserviceinfos, 
				getApprovalSettings(), getNumOfRequiredApprovals(),
				getIncludeInHealthCheck(), isDoEnforceUniquePublicKeys(), isDoEnforceUniqueDistinguishedName(), isDoEnforceUniqueSubjectDNSerialnumber(),
				isUseCertReqHistory(), isUseUserStorage(), isUseCertificateStorage());
		super.setCAInfo(info);
        setCAId(caId);        
        // Create the implementation
        createCAImpl(info);
	}

	@Override
	public byte[] createPKCS7(CryptoToken cryptoToken, Certificate cert, boolean includeChain) throws SignRequestSignatureException {
        log.info(intres.getLocalizedMessage("cvc.info.nocvcpkcs7"));
        return null;
	}    

	@Override
	public byte[] createRequest(CryptoToken cryptoToken, Collection<ASN1Encodable> attributes, String signAlg, Certificate cacert, int signatureKeyPurpose) throws CryptoTokenOfflineException {
	    return impl.createRequest(cryptoToken, attributes, signAlg, cacert, signatureKeyPurpose);
	}

	@Override
    public byte[] createAuthCertSignRequest(CryptoToken cryptoToken, byte[] request) throws CryptoTokenOfflineException {
	    return impl.createAuthCertSignRequest(cryptoToken, request);
    }

	@Override
	public void createOrRemoveLinkCertificate(final CryptoToken cryptoToken, final boolean createLinkCertificate, final CertificateProfile certProfile) throws CryptoTokenOfflineException {
	    final byte[] ret = impl.createOrRemoveLinkCertificate(cryptoToken, createLinkCertificate, certProfile);
	    updateLatestLinkCertificate(ret);
	}
	
	@Override
	public Certificate generateCertificate(CryptoToken cryptoToken, EndEntityInformation subject, 
    		RequestMessage request,
            PublicKey publicKey, 
			int keyusage, 
			Date notBefore,
			Date notAfter,
			CertificateProfile certProfile,
			Extensions extensions,
			String sequence) throws Exception{
	    return impl.generateCertificate(cryptoToken, subject, request, publicKey, keyusage, notBefore, notAfter, certProfile, extensions, sequence);
	}

    @Override
    public X509CRLHolder generateCRL(CryptoToken cryptoToken, Collection<RevokedCertInfo> certs, int crlnumber) {
        String msg = intres.getLocalizedMessage("createcrl.nocrlcreate", "CVC");
        log.info(msg);
        return null;
    }

    @Override
    public X509CRLHolder generateDeltaCRL(CryptoToken cryptoToken, Collection<RevokedCertInfo> certs, int crlnumber, int basecrlnumber) {
        String msg = intres.getLocalizedMessage("createcrl.nocrlcreate", "CVC");
        log.info(msg);
        return null;
    }

	/** Implementation of UpgradableDataHashMap function getLatestVersion */
    @Override
	public float getLatestVersion(){
		return LATEST_VERSION;
	}

	/** Implementation of UpgradableDataHashMap function upgrade. 
	 */
    @Override
	public void upgrade(){
		if(Float.compare(LATEST_VERSION, getVersion()) != 0) {
			// New version of the class, upgrade
            log.info("Upgrading CVCCA with version "+getVersion());

			// Put upgrade code here...
            
            // v1->v2 is only an upgrade in order to upgrade CA token
            // v2->v3 is a upgrade of X509CA that has to be adjusted here too, due to the common heritage
            if (data.get(CRLPERIOD) instanceof Integer) {
            	setCRLPeriod(0L);
            }
            if (data.get(CRLISSUEINTERVAL) instanceof Integer) {
            	setCRLIssueInterval(0L);
            }
            if (data.get(CRLOVERLAPTIME) instanceof Integer) {
            	setCRLOverlapTime(0L);
            }
            if (data.get(DELTACRLPERIOD) instanceof Integer) {
            	setDeltaCRLPeriod(0L);
            }

			data.put(VERSION, new Float(LATEST_VERSION));
		}  
	}

	/**
	 * Method to upgrade new (or existing external caservices)
	 * This method needs to be called outside the regular upgrade
	 * since the CA isn't instantiated in the regular upgrade.
	 */
    @Override
	@SuppressWarnings("deprecation")
    public boolean upgradeExtendedCAServices() {
	    boolean retval = false;
	    Collection<Integer> externalServiceTypes = getExternalCAServiceTypes();
        if (!CesecoreConfiguration.getCaKeepOcspExtendedService() && externalServiceTypes.contains(ExtendedCAServiceTypes.TYPE_OCSPEXTENDEDSERVICE)) {
            //This type has been removed, so remove it from any CAs it's been added to as well.
            externalServiceTypes.remove(ExtendedCAServiceTypes.TYPE_OCSPEXTENDEDSERVICE);
            data.put(EXTENDEDCASERVICES, externalServiceTypes);
            retval = true;
        }
		return retval;
	}

	@Override
	public byte[] decryptData(CryptoToken cryptoToken, byte[] data, int cAKeyPurpose) throws Exception {
		throw new IllegalArgumentException("decryptData not implemented for CVC CA");
	}

    @Override
	public byte[] encryptData(CryptoToken cryptoToken, byte[] data, int keyPurpose) throws Exception {
		throw new IllegalArgumentException("encryptData not implemented for CVC CA");
	}
}

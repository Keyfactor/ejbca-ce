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

package org.ejbca.core.model.ca.caadmin.extendedcaservices;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSSignedGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.KeyTransRecipientId;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.encoders.DecoderException;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAService;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceInfo;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceNotActiveException;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceRequest;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceRequestException;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceResponse;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceTypes;
import org.cesecore.certificates.ca.extendedservices.IllegalExtendedCAServiceRequestException;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.certextensions.AvailableCustomCertificateExtensionsConfiguration;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.StringTools;
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.core.model.InternalEjbcaResources;

/** Handles and maintains the CA-part of the CMS message functionality.
 *  The service has its own certificate used for signing and encryption 
 * 
 * @version $Id$
 */
public class CmsCAService extends ExtendedCAService implements java.io.Serializable{

    /** Determines if a de-serialized file is compatible with this class.
    *
    * Maintainers must change this value if and only if the new version
    * of this class is not compatible with old versions. See Sun docs
    * for <a href=http://java.sun.com/products/jdk/1.1/docs/guide
    * /serialization/spec/version.doc.html> details. </a>
    */
	private static final long serialVersionUID = 5273836489592921586L;
	
	private static final Logger log = Logger.getLogger(CmsCAService.class);
	/** Internal localization of logs and errors */
	private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();

	public static final float LATEST_VERSION = 2; 

	public static final String SERVICENAME = "CMSCASERVICE";          

	private PrivateKey privKey = null;
	private List<Certificate> certificatechain = null;
    private X509Certificate cmsCertificate = null;

	private CmsCAServiceInfo info = null;

	private static final String KEYSTORE       = "keystore"; 
	private static final String KEYSPEC        = "keyspec";
	private static final String KEYALGORITHM   = "keyalgorithm";
	private static final String SUBJECTDN      = "subjectdn";
	private static final String SUBJECTALTNAME = "subjectaltname";

	private static final String PRIVATESIGNKEYALIAS = "signKey";   

	public CmsCAService(final ExtendedCAServiceInfo serviceinfo)  {
		super(serviceinfo);
		if (log.isDebugEnabled()) {
	        log.debug("CmsCAService : constructor " + serviceinfo.getStatus()); 
		}
		CryptoProviderTools.installBCProviderIfNotAvailable();
		// Currently only RSA keys are supported
		final CmsCAServiceInfo info = (CmsCAServiceInfo) serviceinfo;	
		data = new LinkedHashMap<Object, Object>();   
		data.put(ExtendedCAServiceInfo.IMPLEMENTATIONCLASS, this.getClass().getName());	// For integration with CESeCore
		data.put(EXTENDEDCASERVICETYPE, Integer.valueOf(ExtendedCAServiceTypes.TYPE_CMSEXTENDEDSERVICE));	// For current version of EJBCA
		data.put(KEYSPEC, info.getKeySpec());
		data.put(KEYALGORITHM, info.getKeyAlgorithm());
		setSubjectDN(info.getSubjectDN());
		setSubjectAltName(info.getSubjectAltName());                       
		setStatus(serviceinfo.getStatus());
		data.put(VERSION, new Float(LATEST_VERSION));
	}

	public CmsCAService(final HashMap<Object, Object> data) throws IllegalArgumentException {
		super(data);
		CryptoProviderTools.installBCProviderIfNotAvailable();
		loadData(data);
		if (this.data.get(KEYSTORE) != null) {    
			// lookup keystore passwords      
			final String keystorepass = StringTools.passwordDecryption(EjbcaConfiguration.getCaCmsKeyStorePass(), "ca.cmskeystorepass");
			int status = ExtendedCAServiceInfo.STATUS_INACTIVE;
			try {
		        if (log.isDebugEnabled()) {
	                log.debug("Loading CMS keystore");
		        }
				final KeyStore keystore = KeyStore.getInstance("PKCS12", "BC");
				keystore.load(new ByteArrayInputStream(Base64.decode(((String) this.data.get(KEYSTORE)).getBytes())),keystorepass.toCharArray());
                if (log.isDebugEnabled()) {
                    log.debug("Finished loading CMS keystore");
                }
				privKey = (PrivateKey) keystore.getKey(PRIVATESIGNKEYALIAS, null);
				// Due to a bug in Glassfish v1 (fixed in v2), we used to have to make sure all certificates in this 
				// Array were of SUNs own provider, using CertTools.SYSTEM_SECURITY_PROVIDER.
				// As of EJBCA 3.9.3 we decided that we don't have to support Glassfish v1 anymore.
				Collection<Certificate> coll = CertTools.getCertCollectionFromArray(keystore.getCertificateChain(PRIVATESIGNKEYALIAS), null);
				this.certificatechain = new ArrayList<Certificate>(coll);  
				status = getStatus();
			} catch (Exception e) {
				log.error("Could not load keystore or certificate for CA CMS service. Perhaps the password was changed? " + e.getMessage());
			} finally {
				info = new CmsCAServiceInfo(status, getSubjectDN(), getSubjectAltName(), (String)this.data.get(KEYSPEC), 
						(String) this.data.get(KEYALGORITHM), this.certificatechain);
			}
			data.put(EXTENDEDCASERVICETYPE, Integer.valueOf(ExtendedCAServiceTypes.TYPE_CMSEXTENDEDSERVICE));        
		} else {
            if (log.isDebugEnabled()) {
                log.debug("KEYSTORE is null when creating CmsCAService");
            }
		}
	}

	@Override
	public void init(final CryptoToken cryptoToken, final CA ca, final AvailableCustomCertificateExtensionsConfiguration cceConfig) throws Exception {
        if (log.isTraceEnabled()) {
            log.trace(">init");
        }
        if (info.getStatus() != ExtendedCAServiceInfo.STATUS_ACTIVE) {
            if (log.isDebugEnabled()) {
                log.debug("Not generating certificates for inactive service");
            }
        } else {
    		// lookup keystore passwords      
    	    final String keystorepass = StringTools.passwordDecryption(EjbcaConfiguration.getCaCmsKeyStorePass(), "ca.cmskeystorepass");
    		// Currently only RSA keys are supported
    	    final CmsCAServiceInfo info = (CmsCAServiceInfo) getExtendedCAServiceInfo();
    		// Create KeyStore	    
    	    final KeyStore keystore = KeyStore.getInstance("PKCS12", "BC");
    		keystore.load(null, null);                              
    		final KeyPair cmskeys = KeyTools.genKeys(info.getKeySpec(), info.getKeyAlgorithm());
    		// A simple hard coded certificate profile that works for the CMS CA service
    		final CertificateProfile certProfile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
    		certProfile.setUseKeyUsage(true);
    		certProfile.setKeyUsage(new boolean[9]);
    		certProfile.setKeyUsage(CertificateConstants.DIGITALSIGNATURE,true);
    		certProfile.setKeyUsage(CertificateConstants.KEYENCIPHERMENT,true);
    		certProfile.setKeyUsage(CertificateConstants.DATAENCIPHERMENT,true);
    		certProfile.setKeyUsageCritical(true);
    		final Certificate certificate =
    			ca.generateCertificate(cryptoToken, new EndEntityInformation("NOUSERNAME", info.getSubjectDN(), 0, info.getSubjectAltName(), "NOEMAIL", 0,new EndEntityType(),0,0, null,null,0,0,null),
    					cmskeys.getPublic(),
    					-1, // KeyUsage
                        null, // Custom not before date
    					ca.getValidity(),
    					certProfile, 
    					null, // sequence
    					cceConfig // AvailableCustomCertificateExtensionsConfiguration
    			);
    		certificatechain = new ArrayList<Certificate>();
    		certificatechain.add(certificate);
    		certificatechain.addAll(ca.getCertificateChain());
    		privKey = cmskeys.getPrivate(); 
    		keystore.setKeyEntry(PRIVATESIGNKEYALIAS,cmskeys.getPrivate(),null,(Certificate[]) certificatechain.toArray(new Certificate[certificatechain.size()]));              
    		final ByteArrayOutputStream baos = new ByteArrayOutputStream();
    		keystore.store(baos, keystorepass.toCharArray());
    		data.put(KEYSTORE, new String(Base64.encode(baos.toByteArray())));      
	    }
		setStatus(info.getStatus());
		this.info = new CmsCAServiceInfo(info.getStatus(), getSubjectDN(), getSubjectAltName(), (String)data.get(KEYSPEC), (String) data.get(KEYALGORITHM), certificatechain);
        if (log.isTraceEnabled()) {
            log.trace("<init");
        }
	}

	@Override
	public void update(final CryptoToken cryptoToken, final ExtendedCAServiceInfo serviceinfo, final CA ca, final AvailableCustomCertificateExtensionsConfiguration cceConfig) {
	    final boolean missingCert = (!data.containsKey(KEYSTORE) && serviceinfo.getStatus() == ExtendedCAServiceInfo.STATUS_ACTIVE);
		final CmsCAServiceInfo info = (CmsCAServiceInfo) serviceinfo; 
        if (log.isDebugEnabled()) {
            log.debug("CmsCAService : update " + serviceinfo.getStatus());
        }
		setStatus(serviceinfo.getStatus());
		data.put(KEYSPEC, info.getKeySpec());
		data.put(KEYALGORITHM, info.getKeyAlgorithm());
		// We only updated the status, and keyspec/keyalg which can be edited in uninitialized CAs
		this.info = new CmsCAServiceInfo(serviceinfo.getStatus(), getSubjectDN(), getSubjectAltName(), info.getKeySpec(), info.getKeyAlgorithm(), certificatechain);
		if (info.getRenewFlag() || missingCert) {
			// Renew The Signers certificate.
			try {
				this.init(cryptoToken, ca, cceConfig);
			} catch (Exception e) {
				log.error("Error initilizing Extended CA service during upgrade: ", e);
			}
		}
	}

    @Override
    public ExtendedCAServiceResponse extendedService(final CryptoToken cryptoToken, final ExtendedCAServiceRequest request)
            throws ExtendedCAServiceRequestException, IllegalExtendedCAServiceRequestException, ExtendedCAServiceNotActiveException {
        if (log.isTraceEnabled()) {
            log.trace(">extendedService");
        }
		if (!(request instanceof CmsCAServiceRequest)) {
			throw new IllegalExtendedCAServiceRequestException();            
		}
		if (getStatus() != ExtendedCAServiceInfo.STATUS_ACTIVE) {
			final String msg = intres.getLocalizedMessage("caservice.notactive", "CMS");
			log.error(msg);
			throw new ExtendedCAServiceNotActiveException(msg);                            
		}
		ExtendedCAServiceResponse returnval = null;
		final X509Certificate signerCert = (X509Certificate) certificatechain.get(0);
		final CmsCAServiceRequest serviceReq = (CmsCAServiceRequest)request;
		// Create the signed data
		final CMSSignedDataGenerator gen1 = new CMSSignedDataGenerator();
        try {
            byte[] resp = serviceReq.getDoc();
            // Add our signer info and sign the message
            if ((serviceReq.getMode() & CmsCAServiceRequest.MODE_SIGN) != 0) {
                final List<X509Certificate> x509CertChain = new ArrayList<X509Certificate>();
                for (Certificate certificate : certificatechain) {
                    x509CertChain.add((X509Certificate) certificate);
                }
                gen1.addCertificates(new CollectionStore(CertTools.convertToX509CertificateHolder(x509CertChain)));
                JcaDigestCalculatorProviderBuilder calculatorProviderBuilder = new JcaDigestCalculatorProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME);
                JcaSignerInfoGeneratorBuilder builder = new JcaSignerInfoGeneratorBuilder(calculatorProviderBuilder.build());
                ASN1ObjectIdentifier oid = AlgorithmTools.getSignAlgOidFromDigestAndKey(CMSSignedGenerator.DIGEST_SHA1, privKey.getAlgorithm());
                String signatureAlgorithmName = AlgorithmTools.getAlgorithmNameFromOID(oid);
                JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder(signatureAlgorithmName).setProvider(BouncyCastleProvider.PROVIDER_NAME);
                ContentSigner contentSigner = signerBuilder.build(privKey);
                gen1.addSignerInfoGenerator(builder.build(contentSigner, signerCert));
                final CMSTypedData msg = new CMSProcessableByteArray(resp);
                final CMSSignedData s = gen1.generate(msg, true);
                resp = s.getEncoded();
            }
            if ((serviceReq.getMode() & CmsCAServiceRequest.MODE_ENCRYPT) != 0) {
                CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();
                edGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(getCMSCertificate()).setProvider(BouncyCastleProvider.PROVIDER_NAME));
                JceCMSContentEncryptorBuilder jceCMSContentEncryptorBuilder = new JceCMSContentEncryptorBuilder(PKCSObjectIdentifiers.des_EDE3_CBC).setProvider(BouncyCastleProvider.PROVIDER_NAME);
                CMSEnvelopedData ed = edGen.generate(new CMSProcessableByteArray(resp), jceCMSContentEncryptorBuilder.build());
                resp = ed.getEncoded();
			}
			if ((serviceReq.getMode() & CmsCAServiceRequest.MODE_DECRYPT) != 0) {
				final CMSEnvelopedData ed = new CMSEnvelopedData(resp);
				final RecipientInformationStore  recipients = ed.getRecipientInfos();
				final X500Name issuer = X500Name.getInstance(getCMSCertificate().getIssuerX500Principal().getEncoded());
				final KeyTransRecipientId id = new KeyTransRecipientId(issuer, getCMSCertificate().getSerialNumber());
				final RecipientInformation recipient = recipients.get(id);
				if (recipient != null) {
	                JceKeyTransEnvelopedRecipient rec = new JceKeyTransEnvelopedRecipient(this.privKey);
	                // Provider for decrypting the symmetric key 
                    // We can use a different provider for decrypting the content, for example of we used a PKCS#11 provider above we could use the BC provider below
	                rec.setContentProvider(BouncyCastleProvider.PROVIDER_NAME);
	                rec.setProvider(cryptoToken.getSignProviderName());
	                // Option we must set to prevent Java PKCS#11 provider to try to make the symmetric decryption in the HSM, 
	                // even though we set content provider to BC. Symm decryption in HSM varies between different HSMs and at least for this case is known 
	                // to not work in SafeNet Luna (JDK behavior changed in JDK 7_75 where they introduced imho a buggy behavior)
	                rec.setMustProduceEncodableUnwrappedKey(true);	                
	                resp = recipient.getContent(rec);
				}
			}
			returnval = new CmsCAServiceResponse(resp);
        } catch (CMSException e) {
        	log.error("Error in CmsCAService", e);
        	throw new ExtendedCAServiceRequestException(e);
		} catch (IOException e) {
        	log.error("Error in CmsCAService", e);
        	throw new ExtendedCAServiceRequestException(e);
		} catch (OperatorCreationException e) {
		    log.error("Error in CmsCAService", e);
            throw new ExtendedCAServiceRequestException(e);
		} catch (CertificateEncodingException e) {
		    log.error("Error in CmsCAService", e);
            throw new ExtendedCAServiceRequestException(e);
        }
        if (log.isTraceEnabled()) {
            log.trace("<extendedService");              
        }
		return returnval;
	}

	private X509Certificate getCMSCertificate() {
		if (cmsCertificate == null) {
		    for (final Certificate current : certificatechain) {
				final X509Certificate cert = (X509Certificate) current;
				if (cert.getBasicConstraints() == -1) {
					cmsCertificate = cert;
					break;
				}
			}
		}
		return cmsCertificate;
	}

	@Override
	public float getLatestVersion() {		
		return LATEST_VERSION;
	}

	@Override
	public void upgrade() {
		if (Float.compare(LATEST_VERSION, getVersion()) != 0) {
			// New version of the class, upgrade
			data.put(ExtendedCAServiceInfo.IMPLEMENTATIONCLASS, this.getClass().getName());	// For integration with CESeCore
			data.put(VERSION, new Float(LATEST_VERSION));
		}
	}

	@Override
	public ExtendedCAServiceInfo getExtendedCAServiceInfo() {			
		if (info == null) {
			info = new CmsCAServiceInfo(getStatus(), getSubjectDN(), getSubjectAltName(), (String) data.get(KEYSPEC), (String) data.get(KEYALGORITHM), certificatechain);
		}
		return info;
	}

	private String getSubjectDN() {
        return getSubjectXName(SUBJECTDN);
	}

	private void setSubjectDN(final String dn) {
        setSubjectXName(SUBJECTDN, dn);
	}

	private String getSubjectAltName() {
	    return getSubjectXName(SUBJECTALTNAME);
	}

	private void setSubjectAltName(final String an) {
	    setSubjectXName(SUBJECTALTNAME, an);
	}

    private String getSubjectXName(final String key) {
        String ret = null;
        final String value = (String) data.get(key);
        try {
            ret = new String(Base64.decode((value).getBytes("UTF-8")));
        } catch (UnsupportedEncodingException e) {
            log.error("Could not decode data from Base64", e);
        } catch (DecoderException e) {
            // This is an old CA, where it's not Base64encoded
            if (log.isDebugEnabled()) {
                log.debug("Old non base64 encoded " + key + ": " + value);
            }
            ret = value; 
        }
        return ret;       
    }

    private void setSubjectXName(final String key, final String value) {
        try {
            data.put(key, new String(Base64.encode(value.getBytes("UTF-8"), false)));
        } catch (UnsupportedEncodingException e) {
            log.error("Could not encode data to Base64", e);
        }
    }
}

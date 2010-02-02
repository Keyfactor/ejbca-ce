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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Vector;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuingDistributionPoint;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509DefaultEntryConverter;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509ExtensionsGenerator;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.asn1.x509.X509NameEntryConverter;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSSignedGenerator;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.x509.X509V2CRLGenerator;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.ejbca.core.ejb.ca.sign.SernoGenerator;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ca.CAOfflineException;
import org.ejbca.core.model.ca.SignRequestSignatureException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.CmsCAService;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.CmsCAServiceInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.XKMSCAService;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.XKMSCAServiceInfo;
import org.ejbca.core.model.ca.catoken.CATokenConstants;
import org.ejbca.core.model.ca.catoken.CATokenContainer;
import org.ejbca.core.model.ca.catoken.CATokenInfo;
import org.ejbca.core.model.ca.catoken.CATokenOfflineException;
import org.ejbca.core.model.ca.catoken.NullCATokenInfo;
import org.ejbca.core.model.ca.certextensions.CertificateExtension;
import org.ejbca.core.model.ca.certextensions.CertificateExtensionFactory;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfile;
import org.ejbca.core.model.ca.certificateprofiles.RootCACertificateProfile;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.util.CertTools;
import org.ejbca.util.SimpleTime;
import org.ejbca.util.StringTools;
import org.ejbca.util.cert.PrintableStringEntryConverter;
import org.ejbca.util.dn.DnComponents;




/**
 * X509CA is a implementation of a CA and holds data specific for Certificate and CRL generation 
 * according to the X509 standard. 
 *
 * @version $Id$
 */
public class X509CA extends CA implements Serializable {

    private static final Logger log = Logger.getLogger(X509CA.class);

    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    /** Version of this class, if this is increased the upgrade() method will be called automatically */
    public static final float LATEST_VERSION = 19;

    /** key ID used for identifier of key used for key recovery encryption */
    private byte[]  keyId = new byte[] { 1, 2, 3, 4, 5 };
    
    
    // protected fields for properties specific to this type of CA.
    protected static final String POLICIES                       = "policies";
    protected static final String SUBJECTALTNAME                 = "subjectaltname";
    protected static final String USEAUTHORITYKEYIDENTIFIER      = "useauthoritykeyidentifier";
    protected static final String AUTHORITYKEYIDENTIFIERCRITICAL = "authoritykeyidentifiercritical";
    protected static final String USECRLNUMBER                   = "usecrlnumber";
    protected static final String CRLNUMBERCRITICAL              = "crlnumbercritical";
    protected static final String DEFAULTCRLDISTPOINT            = "defaultcrldistpoint";
    protected static final String DEFAULTCRLISSUER               = "defaultcrlissuer";
    protected static final String DEFAULTOCSPSERVICELOCATOR      = "defaultocspservicelocator";
    protected static final String CADEFINEDFRESHESTCRL           = "cadefinedfreshestcrl";
    protected static final String USEUTF8POLICYTEXT              = "useutf8policytext";
    protected static final String USEPRINTABLESTRINGSUBJECTDN    = "useprintablestringsubjectdn";
    protected static final String USELDAPDNORDER                 = "useldapdnorder";
    protected static final String USECRLDISTRIBUTIONPOINTONCRL   = "usecrldistributionpointoncrl";
    protected static final String CRLDISTRIBUTIONPOINTONCRLCRITICAL = "crldistributionpointoncrlcritical";

    // Public Methods
    /** Creates a new instance of CA, this constructor should be used when a new CA is created */
    public X509CA(X509CAInfo cainfo) {
      super(cainfo);  
      
      data.put(POLICIES, cainfo.getPolicies());
      data.put(SUBJECTALTNAME,  cainfo.getSubjectAltName());            
      setUseAuthorityKeyIdentifier(cainfo.getUseAuthorityKeyIdentifier());
      setAuthorityKeyIdentifierCritical(cainfo.getAuthorityKeyIdentifierCritical()); 
      setUseCRLNumber(cainfo.getUseCRLNumber());
      setCRLNumberCritical(cainfo.getCRLNumberCritical());
      setDefaultCRLDistPoint(cainfo.getDefaultCRLDistPoint());
      setDefaultCRLIssuer(cainfo.getDefaultCRLIssuer());
      setCADefinedFreshestCRL(cainfo.getCADefinedFreshestCRL());
      setDefaultOCSPServiceLocator(cainfo.getDefaultOCSPServiceLocator());
      setFinishUser(cainfo.getFinishUser());
      setUseUTF8PolicyText(cainfo.getUseUTF8PolicyText());
      setUsePrintableStringSubjectDN(cainfo.getUsePrintableStringSubjectDN());
      setUseLdapDNOrder(cainfo.getUseLdapDnOrder());
      setUseCrlDistributionPointOnCrl(cainfo.getUseCrlDistributionPointOnCrl());
      setCrlDistributionPointOnCrlCritical(cainfo.getCrlDistributionPointOnCrlCritical());
      setIncludeInHealthCheck(cainfo.getIncludeInHealthCheck());

      data.put(CA.CATYPE, new Integer(CAInfo.CATYPE_X509));
      data.put(VERSION, new Float(LATEST_VERSION));   
    }
    
   /** Constructor used when retrieving existing X509CA from database. 
 * @throws IllegalKeyStoreException */
    public X509CA(HashMap data, int caId, String subjectDN, String name, int status, Date updateTime, Date expireTime) throws IllegalKeyStoreException{
    	super(data);
    	setExpireTime(expireTime);	// Make sure the internal state is synched with the database column. Required for upgrades from EJBCA 3.5.6 or EJBCA 3.6.1 and earlier.
    	ArrayList externalcaserviceinfos = new ArrayList();
    	Iterator iter = getExternalCAServiceTypes().iterator(); 	
    	while(iter.hasNext()){
    		ExtendedCAServiceInfo info = this.getExtendedCAServiceInfo(((Integer) iter.next()).intValue());
    		if (info != null) {
        		externalcaserviceinfos.add(info);  	    			
    		}
    	}
        CAInfo info = new X509CAInfo(subjectDN, name, status, updateTime, getSubjectAltName() ,getCertificateProfileId(),  
        		  getValidity(), getExpireTime(), getCAType(), getSignedBy(), getCertificateChain(),
        		  getCAToken(caId).getCATokenInfo(), getDescription(), getRevokationReason(), getRevokationDate(), getPolicies(), getCRLPeriod(), getCRLIssueInterval(), getCRLOverlapTime(), getDeltaCRLPeriod(), getCRLPublishers(),
        		  getUseAuthorityKeyIdentifier(), getAuthorityKeyIdentifierCritical(),
        		  getUseCRLNumber(), getCRLNumberCritical(), getDefaultCRLDistPoint(), getDefaultCRLIssuer(), getDefaultOCSPServiceLocator(), getCADefinedFreshestCRL(), getFinishUser(), externalcaserviceinfos, 
        		  getUseUTF8PolicyText(), getApprovalSettings(), getNumOfRequiredApprovals(), getUsePrintableStringSubjectDN(), getUseLdapDNOrder(),
        		  getUseCrlDistributionPointOnCrl(), getCrlDistributionPointOnCrlCritical(),getIncludeInHealthCheck());
        super.setCAInfo(info);
    }

    // Public Methods.
    public List getPolicies() {
    	return (List) data.get(POLICIES);
    }
    public void setPolicies(List policies) {
    	data.put(POLICIES, policies);
    }
    
    public String getSubjectAltName() { return (String) data.get(SUBJECTALTNAME);}
    
    public boolean  getUseAuthorityKeyIdentifier(){
      return ((Boolean)data.get(USEAUTHORITYKEYIDENTIFIER)).booleanValue();
    }
    public void setUseAuthorityKeyIdentifier(boolean useauthoritykeyidentifier) {
      data.put(USEAUTHORITYKEYIDENTIFIER, Boolean.valueOf(useauthoritykeyidentifier));
    }
    
    public boolean  getAuthorityKeyIdentifierCritical(){
      return ((Boolean)data.get(AUTHORITYKEYIDENTIFIERCRITICAL)).booleanValue();
    }
    public void setAuthorityKeyIdentifierCritical(boolean authoritykeyidentifiercritical) {
      data.put(AUTHORITYKEYIDENTIFIERCRITICAL, Boolean.valueOf(authoritykeyidentifiercritical));
    }

    public boolean  getUseCRLNumber(){return ((Boolean)data.get(USECRLNUMBER)).booleanValue();}
    public void setUseCRLNumber(boolean usecrlnumber) {data.put(USECRLNUMBER, Boolean.valueOf(usecrlnumber));}
    
    public boolean  getCRLNumberCritical(){return ((Boolean)data.get(CRLNUMBERCRITICAL)).booleanValue();}
    public void setCRLNumberCritical(boolean crlnumbercritical) {data.put(CRLNUMBERCRITICAL, Boolean.valueOf(crlnumbercritical));}
    
    public String  getDefaultCRLDistPoint(){return (String) data.get(DEFAULTCRLDISTPOINT);}
    public void setDefaultCRLDistPoint(String defaultcrldistpoint) {
    	if(defaultcrldistpoint == null){
    		data.put(DEFAULTCRLDISTPOINT, "");
    	}else{
    		data.put(DEFAULTCRLDISTPOINT, defaultcrldistpoint);
    	}     
    }
    public String  getDefaultCRLIssuer(){return (String) data.get(DEFAULTCRLISSUER);}
    public void setDefaultCRLIssuer(String defaultcrlissuer) {
    	if(defaultcrlissuer == null){
    		data.put(DEFAULTCRLISSUER, "");
    	}else{
    		data.put(DEFAULTCRLISSUER, defaultcrlissuer);
    	}     
    }
    
    public String  getCADefinedFreshestCRL(){
        return (String) data.get(CADEFINEDFRESHESTCRL);
    }
    
    public void setCADefinedFreshestCRL(String cadefinedfreshestcrl) {
        if(cadefinedfreshestcrl == null){
            data.put(CADEFINEDFRESHESTCRL, "");
        }else{
            data.put(CADEFINEDFRESHESTCRL, cadefinedfreshestcrl);
        }     
    }
    public String  getDefaultOCSPServiceLocator(){return (String) data.get(DEFAULTOCSPSERVICELOCATOR);}
    public void setDefaultOCSPServiceLocator(String defaultocsplocator) {
    	if(defaultocsplocator == null){
    		data.put(DEFAULTOCSPSERVICELOCATOR, "");
    	}else{
    		data.put(DEFAULTOCSPSERVICELOCATOR, defaultocsplocator);
    	}     
    }

    public boolean  getUseUTF8PolicyText(){
        return ((Boolean)data.get(USEUTF8POLICYTEXT)).booleanValue();
      }
      public void setUseUTF8PolicyText(boolean useutf8) {
        data.put(USEUTF8POLICYTEXT, Boolean.valueOf(useutf8));
      }

      public boolean  getUsePrintableStringSubjectDN(){
    	  return ((Boolean)data.get(USEPRINTABLESTRINGSUBJECTDN)).booleanValue();
      }
      public void setUsePrintableStringSubjectDN(boolean useprintablestring) {
    	  data.put(USEPRINTABLESTRINGSUBJECTDN, Boolean.valueOf(useprintablestring));
      }

      public boolean  getUseLdapDNOrder(){
    	  return ((Boolean)data.get(USELDAPDNORDER)).booleanValue();
      }
      public void setUseLdapDNOrder(boolean useldapdnorder) {
    	  data.put(USELDAPDNORDER, Boolean.valueOf(useldapdnorder));
      }

      public boolean getUseCrlDistributionPointOnCrl() {
          return ((Boolean)data.get(USECRLDISTRIBUTIONPOINTONCRL)).booleanValue();
      }

      public void setUseCrlDistributionPointOnCrl(boolean useCrlDistributionPointOnCrl) {
          data.put(USECRLDISTRIBUTIONPOINTONCRL, Boolean.valueOf(useCrlDistributionPointOnCrl));
      }

      public boolean getCrlDistributionPointOnCrlCritical() {
          return ((Boolean)data.get(CRLDISTRIBUTIONPOINTONCRLCRITICAL)).booleanValue();
      }

      public void setCrlDistributionPointOnCrlCritical(boolean crlDistributionPointOnCrlCritical) {
          data.put(CRLDISTRIBUTIONPOINTONCRLCRITICAL, Boolean.valueOf(crlDistributionPointOnCrlCritical));
      }

      public void updateCA(CAInfo cainfo) throws Exception{
    	  super.updateCA(cainfo); 
    	  X509CAInfo info = (X509CAInfo) cainfo;
    	  
    	  setUseAuthorityKeyIdentifier(info.getUseAuthorityKeyIdentifier());
    	  setAuthorityKeyIdentifierCritical(info.getAuthorityKeyIdentifierCritical()); 
    	  setUseCRLNumber(info.getUseCRLNumber());
    	  setCRLNumberCritical(info.getCRLNumberCritical());
    	  setDefaultCRLDistPoint(info.getDefaultCRLDistPoint());
    	  setDefaultCRLIssuer(info.getDefaultCRLIssuer());
          setCADefinedFreshestCRL(info.getCADefinedFreshestCRL());
    	  setDefaultOCSPServiceLocator(info.getDefaultOCSPServiceLocator());
    	  setUseUTF8PolicyText(info.getUseUTF8PolicyText());
          setUsePrintableStringSubjectDN(info.getUsePrintableStringSubjectDN());
          setUseLdapDNOrder(info.getUseLdapDnOrder());
          setUseCrlDistributionPointOnCrl(info.getUseCrlDistributionPointOnCrl());
          setCrlDistributionPointOnCrlCritical(info.getCrlDistributionPointOnCrlCritical());
      }
    

    public byte[] createPKCS7(Certificate cert, boolean includeChain) throws SignRequestSignatureException {
        // First verify that we signed this certificate
        try {
            if (cert != null) {
                cert.verify(getCAToken().getPublicKey(SecConst.CAKEYPURPOSE_CERTSIGN));
            }
        } catch (Exception e) {
            throw new SignRequestSignatureException("Cannot verify certificate in createPKCS7(), did I sign this?");
        }
        Collection chain = getCertificateChain();
        ArrayList certList = new ArrayList();
        if (cert != null) {
            certList.add(cert);
        } 
        if (includeChain) {
            certList.addAll(chain);
        }
        try {
            CMSProcessable msg = new CMSProcessableByteArray("EJBCA".getBytes());
            CertStore certs = CertStore.getInstance("Collection", new CollectionCertStoreParameters(certList), "BC");
            CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
            if (getCAToken().getPrivateKey(SecConst.CAKEYPURPOSE_CERTSIGN) == null) {
            	String msg1 = "createPKCS7: Private key does not exist!";
            	log.debug(msg1);
            	throw new SignRequestSignatureException(msg1);
            }
            gen.addSigner(getCAToken().getPrivateKey(SecConst.CAKEYPURPOSE_CERTSIGN), (X509Certificate)getCACertificate(), CMSSignedGenerator.DIGEST_SHA1);
            gen.addCertificatesAndCRLs(certs);
            CMSSignedData s = null;
            CATokenContainer catoken = getCAToken();
            CATokenInfo tokeninfo = getCAInfo().getCATokenInfo();
            if (catoken != null && !(tokeninfo instanceof NullCATokenInfo)) {
            	log.debug("createPKCS7: Provider="+catoken.getProvider()+" using algorithm "+getCAToken().getPrivateKey(SecConst.CAKEYPURPOSE_CERTSIGN).getAlgorithm());
            	s = gen.generate(msg, true, catoken.getProvider());
            } else {
            	String msg1 = "CA Token does not exist!";
            	log.debug(msg);
            	throw new SignRequestSignatureException(msg1);
            }
            return s.getEncoded();
        } catch (CATokenOfflineException e) {
        	throw new RuntimeException(e);        	
        } catch (Exception e) {
            throw new RuntimeException(e);
        }   
    }    
    
    /**
     * @see CA#createRequest(Collection, String)
     */
    public byte[] createRequest(Collection attributes, String signAlg, Certificate cacert) throws CATokenOfflineException {
    	ASN1Set attrset = new DERSet();
    	if (attributes != null) {
    		log.debug("Adding attributes in the request");
    		Iterator iter = attributes.iterator();
			ASN1EncodableVector vec = new ASN1EncodableVector();
    		while (iter.hasNext()) {
    			DEREncodable o = (DEREncodable)iter.next();
    			vec.add(o);
    			attrset = new DERSet(vec);
    		}
    	}
        X509NameEntryConverter converter = null;
        if (getUsePrintableStringSubjectDN()) {
        	converter = new PrintableStringEntryConverter();
        } else {
        	converter = new X509DefaultEntryConverter();
        }
        Vector dnorder = CertTools.getX509FieldOrder(getUseLdapDNOrder());
        X509Name x509dn = CertTools.stringToBcX509Name(getSubjectDN(), converter, dnorder);
        PKCS10CertificationRequest req;
		try {
			req = new PKCS10CertificationRequest(signAlg,
					x509dn, getCAToken().getPublicKey(SecConst.CAKEYPURPOSE_CERTSIGN), attrset, getCAToken().getPrivateKey(SecConst.CAKEYPURPOSE_CERTSIGN), getCAToken().getProvider());
	        return req.getEncoded();
		} catch (CATokenOfflineException e) {
			throw e;
		} catch (Exception e) {
            throw new RuntimeException(e);
		} 
    }

	/** If request is an CA certificate, useprevious==true and createlinkcert==true it returns a new certificate signed with the CAs keys. This can be used
	 * to create a NewWithOld certificate for CA key rollover. This method can only create a self-signed certificate and only uses the public key from the passed in certificate.
	 * If the passed in certificate is not signed by the CAs signature key and does not have the same DN as the current CA, null certificate is returned. 
	 * This is because we do not want to create anything else than a NewWithOld certificate, because that would be a security risk. Regular certificates must be issued using createCertificate.
	 * 
	 * Note: Creating the NewWithOld will only work correctly for Root CAs.
	 * 
	 * If request is a CSR (pkcs10) it returns null.
	 * 
	 * @see CA#signRequest(Collection, String)
	 */
	public byte[] signRequest(byte[] request, boolean usepreviouskey, boolean createlinkcert) throws CATokenOfflineException {
		byte[] ret = null;
		try {
			// Get either the current or the previous signing key for signing this request
			int key = SecConst.CAKEYPURPOSE_CERTSIGN;
			if (usepreviouskey) {
				log.debug("Using previous CertSign key to sign certificate");
				key = SecConst.CAKEYPURPOSE_CERTSIGN_PREVIOUS;
			} else {
				log.debug("Using current CertSign key to sign certificate");
			}
			CATokenContainer catoken = getCAToken();

			byte[] binbytes = request;
			X509Certificate cert = null;
			try {
				// We don't know if this is a PEM or binary certificate so we first try to 
				// decode it as a PEM certificate, and if it's not we try it as a binary certificate 
				Collection col = CertTools.getCertsFromPEM(new ByteArrayInputStream(request));
				cert = (X509Certificate)col.iterator().next();
				if (cert != null) {
					binbytes = cert.getEncoded();
				}
			} catch (Exception e) {
				log.debug("This is not a PEM certificate?: "+e.getMessage());
			}
			cert = (X509Certificate)CertTools.getCertfromByteArray(binbytes);
			// Check if the input was a CA certificate, which is the same CA as this. If all is true we should create a NewWithOld link-certificate
			X509Certificate cacert = (X509Certificate)getCACertificate();
			if (CertTools.getSubjectDN(cert).equals(CertTools.getSubjectDN(cacert))) {
	            PublicKey currentCaPublicKey = catoken.getPublicKey(SecConst.CAKEYPURPOSE_CERTSIGN);
				cert.verify(currentCaPublicKey); // Throws SignatureException if verify fails
				if (createlinkcert && usepreviouskey) {
					log.debug("We will create a link certificate.");
					X509CAInfo info = (X509CAInfo)getCAInfo();
	        		UserDataVO cadata = new UserDataVO("nobody", info.getSubjectDN(), info.getSubjectDN().hashCode(), info.getSubjectAltName(), null,
	        				0,0,0,  info.getCertificateProfileId(), null, null, 0, 0, null);
					
					CertificateProfile certProfile = new RootCACertificateProfile();
		        	if((info.getPolicies() != null) && (info.getPolicies().size() > 0)) {
		        		certProfile.setUseCertificatePolicies(true);
		        		certProfile.setCertificatePolicies(info.getPolicies());
		        	}				
		            PublicKey previousCaPublicKey = catoken.getPublicKey(SecConst.CAKEYPURPOSE_CERTSIGN_PREVIOUS);
		            PrivateKey previousCaPrivateKey = catoken.getPrivateKey(SecConst.CAKEYPURPOSE_CERTSIGN_PREVIOUS);
		            String provider = catoken.getProvider();
		        	String sequence = catoken.getCATokenInfo().getKeySequence(); // get from CAtoken to make sure it is fresh
	        		Certificate retcert = generateCertificate(cadata, null, cert.getPublicKey(),-1, cert.getNotBefore(), cert.getNotAfter(), certProfile, null, sequence, previousCaPublicKey, previousCaPrivateKey, provider);
					log.debug("Signed an X509Certificate: '"+cadata.getDN()+"'.");
					String msg = intres.getLocalizedMessage("cvc.info.createlinkcert", cadata.getDN(), cadata.getDN());
					log.info(msg);
					ret = retcert.getEncoded();
				} else {
					log.debug("Not signing any certificate, useprevious="+usepreviouskey+", createlinkcert="+createlinkcert);
				}
			} else {
				log.debug("Not signing any certificate, certSubjectDN != cacertSubjectDN.");				
			}
			
		} catch (IllegalKeyStoreException e) {
			throw new javax.ejb.EJBException(e);
		} catch (SignatureException e) {
			log.debug("Not signing any certificate, input certificate did not verify with current CA signing key.");				
			// Will return request as it was			
		} catch (CertificateException e) {
			log.debug("Not signing any certificate, input was not a certificate.");				
			// It was not a certificate, will return request as it was
		} catch (Exception e) {
			throw new javax.ejb.EJBException(e);
		} 
		return ret;
	}

    public Certificate generateCertificate(UserDataVO subject, 
            X509Name requestX509Name,
            PublicKey publicKey, 
            int keyusage, 
            Date notBefore,
            Date notAfter,
            CertificateProfile certProfile,
            X509Extensions extensions,
            String sequence) throws Exception {
    	// Before we start, check if the CA is off-line, we don't have to waste time
    	// one the stuff below of we are off-line. The line below will throw CATokenOfflineException of CA is offline
    	CATokenContainer catoken = getCAToken();
        PublicKey caPublicKey = catoken.getPublicKey(SecConst.CAKEYPURPOSE_CERTSIGN);
        PrivateKey caPrivateKey = catoken.getPrivateKey(SecConst.CAKEYPURPOSE_CERTSIGN);
        String provider = catoken.getProvider();
    	return generateCertificate(subject, requestX509Name, publicKey, keyusage, notBefore, notAfter, certProfile, extensions, sequence, caPublicKey, caPrivateKey, provider);
    }
	/**
	 * sequence is ignored by X509CA
	 */
    public Certificate generateCertificate(UserDataVO subject, 
    		                               X509Name requestX509Name,
                                           PublicKey publicKey, 
                                           int keyusage, 
                                           Date notBefore,
                                           Date notAfter,
                                           CertificateProfile certProfile,
                                           X509Extensions extensions,
                                           String sequence,
                                           PublicKey caPublicKey, PrivateKey caPrivateKey, String provider) throws Exception {

        // We must only allow signing to take place if the CA itself if on line, even if the token is on-line.
        // We have to allow expired as well though, so we can renew expired CAs
        if ((getStatus() != SecConst.CA_ACTIVE) && ((getStatus() != SecConst.CA_EXPIRED))) {
        	String msg = intres.getLocalizedMessage("error.caoffline", getName(), getStatus());
			log.debug(msg); // This is something we handle so no need to log with higher priority
        	throw new CAOfflineException(msg);
        }

        final String sigAlg;
        if(certProfile.getSignatureAlgorithm() == null) {
            sigAlg = getCAInfo().getCATokenInfo().getSignatureAlgorithm();
        } else {
            sigAlg = certProfile.getSignatureAlgorithm();
        }
        X509Certificate cacert = (X509Certificate)getCACertificate();
        String dn = subject.getDN();        
        // Check if this is a root CA we are creating
        boolean isRootCA = false;
        if (certProfile.getType() == CertificateProfile.TYPE_ROOTCA) {
        	isRootCA = true;
        }
        // Get certificate validity time notBefore and notAfter
        CertificateValidity val = new CertificateValidity(subject, certProfile, notBefore, notAfter, cacert, isRootCA);
        
        X509V3CertificateGenerator certgen = new X509V3CertificateGenerator();
        // Serialnumber is random bits, where random generator is initialized by the
        // serno generator.
        BigInteger serno = SernoGenerator.instance().getSerno();
        certgen.setSerialNumber(serno);
        certgen.setNotBefore(val.getNotBefore());
        certgen.setNotAfter(val.getNotAfter());
        certgen.setSignatureAlgorithm(sigAlg);

        // Make DNs
        if(certProfile.getUseSubjectDNSubSet()){
        	dn= certProfile.createSubjectDNSubSet(dn);	
        }
        
        if(certProfile.getUseCNPostfix()){
          dn = CertTools.insertCNPostfix(dn,certProfile.getCNPostfix());	
        }
                
        X509NameEntryConverter converter = null;
        if (getUsePrintableStringSubjectDN()) {
        	converter = new PrintableStringEntryConverter();
        } else {
        	converter = new X509DefaultEntryConverter();
        }
        // Will we use LDAP DN order (CN first) or X500 DN order (CN last) for the subject DN
        boolean ldapdnorder = true;
        if ((getUseLdapDNOrder() == false) || (certProfile.getUseLdapDnOrder() == false)) {
        	ldapdnorder = false;
        }
        Vector dnorder = CertTools.getX509FieldOrder(ldapdnorder);
        X509Name subjectDNName = CertTools.stringToBcX509Name(dn, converter, dnorder);
        if (certProfile.getAllowDNOverride() && (requestX509Name != null) ) {
        	subjectDNName = requestX509Name;
        	log.debug("Using X509Name from request instead of user's registered.");
        }
        log.debug("Using subjectDN: "+subjectDNName.toString());
        certgen.setSubjectDN(subjectDNName);
        // We must take the issuer DN directly from the CA-certificate otherwise we risk re-ordering the DN
        // which many applications do not like.
        if (isRootCA) {
        	// This will be an initial root CA, since no CA-certificate exists
        	// Or it is a root CA, since the cert is self signed. If it is a root CA we want to use the same encoding for subject and issuer,
        	// it might have changed over the years.
        	if (log.isDebugEnabled()) {
        		log.debug("Using subject DN also as issuer DN, because it is a root CA");
        	}
            X509Name caname = CertTools.stringToBcX509Name(getSubjectDN(), converter, dnorder);
            certgen.setIssuerDN(caname);
        } else {
        	javax.security.auth.x500.X500Principal issuerPrincipal = cacert.getSubjectX500Principal();
        	if (log.isDebugEnabled()) {
        		log.debug("Using issuer DN directly from the CA certificate: "+issuerPrincipal.getName());
        	}
            certgen.setIssuerDN(issuerPrincipal);        	
        }
        certgen.setPublicKey(publicKey);

        //
        // X509 Certificate Extensions
        //
        
        // Extensions we will add to the cetificate, later when we have filled the structure with 
        // everything we want.
        X509ExtensionsGenerator extgen = new X509ExtensionsGenerator();
        
        // First we check if there is general extension override, and add all extensions from 
        // the request in that case
        if (certProfile.getAllowExtensionOverride() && extensions!=null) {
        	Enumeration en = extensions.oids();
        	while (en!=null && en.hasMoreElements()) {
        		DERObjectIdentifier oid = (DERObjectIdentifier)en.nextElement();
        		X509Extension ext = extensions.getExtension(oid);
        		log.debug("Overriding extension with oid: "+oid);
        		extgen.addExtension(oid, ext.isCritical(), ext.getValue().getOctets());
        	}
        }
        
        // Second we see if there is Key usage override
    	X509Extensions overridenexts = extgen.generate();
        if (certProfile.getAllowKeyUsageOverride() && (keyusage >= 0)) {
        	log.debug("AllowKeyUsageOverride=true. Using KeyUsage from parameter: "+keyusage);
            if ( (certProfile.getUseKeyUsage() == true) && (keyusage >=0) ){
                X509KeyUsage ku = new X509KeyUsage(keyusage);
             	// We don't want to try to add custom extensions with the same oid if we have already added them 
             	// from the request, if AllowExtensionOverride is enabled.
             	// Two extensions with the same oid is not allowed in the standard.
        		 if (overridenexts.getExtension(X509Extensions.KeyUsage) == null) {
                     extgen.addExtension(
                             X509Extensions.KeyUsage, certProfile.getKeyUsageCritical(), ku);        			 
        		 } else {
        			 log.debug("KeyUsage was already overridden by an extension, not using KeyUsage from parameter.");
        		 }
            }
        } 
        
        // Third, check for standard Certificate Extensions that should be added.
        // Standard certificate extensions are defined in CertificateProfile and CertificateExtensionFactory
        // and implemented in package org.ejbca.core.model.certextensions.standard
        CertificateExtensionFactory fact = CertificateExtensionFactory.getInstance();
        List usedStdCertExt = certProfile.getUsedStandardCertificateExtensions();
        Iterator certStdExtIter = usedStdCertExt.iterator();
    	overridenexts = extgen.generate();
        while(certStdExtIter.hasNext()){
        	String oid = (String)certStdExtIter.next();
         	// We don't want to try to add standard extensions with the same oid if we have already added them 
        	// from the request, if AllowExtensionOverride is enabled.
        	// Two extensions with the same oid is not allowed in the standard.
        	if (overridenexts.getExtension(new DERObjectIdentifier(oid)) == null) {
            	CertificateExtension certExt = fact.getStandardCertificateExtension(oid, certProfile);
            	if (certExt != null) {
            		DEREncodable value = certExt.getValue(subject, this, certProfile, publicKey, caPublicKey);
            		if (value != null) {
            			extgen.addExtension(new DERObjectIdentifier(certExt.getOID()),certExt.isCriticalFlag(),value);        	         		         			 
            		}
            	}        		
        	} else {
        		log.debug("Extension with oid "+oid+" has been overridden, standard extension will not be added.");
        	}
        }

         // Fourth, check for custom Certificate Extensions that should be added.
         // Custom certificate extensions is defined in certextensions.properties
         fact = CertificateExtensionFactory.getInstance();
         List usedCertExt = certProfile.getUsedCertificateExtensions();
         Iterator certExtIter = usedCertExt.iterator();
         while(certExtIter.hasNext()){
        	 Integer id = (Integer) certExtIter.next();
        	 CertificateExtension certExt = fact.getCertificateExtensions(id);
        	 if (certExt != null) {
             	// We don't want to try to add custom extensions with the same oid if we have already added them 
             	// from the request, if AllowExtensionOverride is enabled.
             	// Two extensions with the same oid is not allowed in the standard.
        		 if (overridenexts.getExtension(new DERObjectIdentifier(certExt.getOID())) == null) {
        			 DEREncodable value = certExt.getValue(subject, this, certProfile, publicKey, caPublicKey);
        			 if (value != null) {
        				 extgen.addExtension(new DERObjectIdentifier(certExt.getOID()),certExt.isCriticalFlag(),value);        	         		         			 
        			 }             		
        		 } else {
             		log.debug("Extension with oid "+certExt.getOID()+" has been overridden, custom extension will not be added.");
             	}
        	 }
         }
         
         // Finally add extensions to certificate generator
         X509Extensions exts = extgen.generate();
         Enumeration en = exts.oids();
         while (en.hasMoreElements()) {
        	 DERObjectIdentifier oid = (DERObjectIdentifier)en.nextElement();
        	 X509Extension ext = exts.getExtension(oid);
        	 certgen.addExtension(oid, ext.isCritical(), ext.getValue().getOctets());
         }
         
         //
         // End of extensions
         //
         
         X509Certificate cert;
         cert = certgen.generate(caPrivateKey, provider);
        
        // Verify before returning
        cert.verify(caPublicKey);
        
        // If we have a CA-certificate, verify that we have all path verification stuff correct
        if (cacert != null) {
        	byte[] aki = CertTools.getAuthorityKeyId(cert);
        	byte[] ski = CertTools.getSubjectKeyId(cacert);
        	if ( (aki != null) && (ski != null) ) {
            	boolean eq = Arrays.equals(aki, ski);
            	if (!eq) {
            		String akistr = new String(Hex.encode(aki));
            		String skistr = new String(Hex.encode(ski));
    				log.error(intres.getLocalizedMessage("signsession.errorpathverifykeyid",akistr, skistr));
            	}        		
        	}
        	Principal issuerDN = cert.getIssuerX500Principal();
        	Principal subjectDN = cacert.getSubjectX500Principal();
        	if ( (issuerDN != null) && (subjectDN != null) ) {
        		boolean eq = issuerDN.equals(subjectDN);
            	if (!eq) {
    				log.error(intres.getLocalizedMessage("signsession.errorpathverifydn",issuerDN.getName(), subjectDN.getName()));
            	}        		
        	}
        }
        log.debug("X509CA: generated certificate, CA "+ this.getCAId() + " for DN: " + subject.getDN());
      return cert;                                                                                        
    }

    
    public CRL generateCRL(Collection certs, int crlnumber) 
    throws CATokenOfflineException, IllegalKeyStoreException, IOException, SignatureException, NoSuchProviderException, InvalidKeyException, CRLException, NoSuchAlgorithmException {
    	return generateCRL(certs, getCRLPeriod(), crlnumber, false, 0);
    }

    public CRL generateDeltaCRL(Collection certs, int crlnumber, int basecrlnumber)
        throws CATokenOfflineException, IllegalKeyStoreException, IOException, SignatureException, NoSuchProviderException, InvalidKeyException, CRLException, NoSuchAlgorithmException {
    	return generateCRL(certs, getDeltaCRLPeriod(), crlnumber, true, basecrlnumber);
    }

    
    /** Generate a CRL or a deltaCRL
     * 
     * @param certs list of revoked certificates
     * @param crlnumber CRLNumber for this CRL
     * @param isDeltaCRL true if we should generate a DeltaCRL
     * @param basecrlnumber caseCRLNumber for a delta CRL, use 0 for full CRLs
     * @param certProfile certificate profile for CRL Distribution point in the CRL, or null
     * @return CRL
     * @throws CATokenOfflineException
     * @throws IllegalKeyStoreException
     * @throws IOException
     * @throws SignatureException
     * @throws NoSuchProviderException
     * @throws InvalidKeyException
     * @throws CRLException
     * @throws NoSuchAlgorithmException
     */
    private CRL generateCRL(Collection certs, long crlPeriod, int crlnumber, boolean isDeltaCRL, int basecrlnumber) 
    throws CATokenOfflineException, IllegalKeyStoreException, IOException, SignatureException, NoSuchProviderException, InvalidKeyException, CRLException, NoSuchAlgorithmException {
        final String sigAlg= getCAInfo().getCATokenInfo().getSignatureAlgorithm();

        if (log.isDebugEnabled()) {
            log.debug("generateCRL("+certs.size()+", "+crlPeriod+", "+crlnumber+", "+isDeltaCRL+", "+basecrlnumber);        	
        }
        Date thisUpdate = new Date();
        Date nextUpdate = new Date();

        nextUpdate.setTime(nextUpdate.getTime() + crlPeriod);
        X509V2CRLGenerator crlgen = new X509V2CRLGenerator();
        crlgen.setThisUpdate(thisUpdate);
        crlgen.setNextUpdate(nextUpdate);
        crlgen.setSignatureAlgorithm(sigAlg);
        // Make DNs
        X509Certificate cacert = (X509Certificate)getCACertificate();
        if (cacert == null) {
        	// This is an initial root CA, since no CA-certificate exists
        	// (I don't think we can ever get here!!!)
            X509NameEntryConverter converter = null;
            if (getUsePrintableStringSubjectDN()) {
            	converter = new PrintableStringEntryConverter();
            } else {
            	converter = new X509DefaultEntryConverter();
            }

            X509Name caname = CertTools.stringToBcX509Name(getSubjectDN(), converter, CertTools.getX509FieldOrder(getUseLdapDNOrder()));
            crlgen.setIssuerDN(caname);
        } else {
        	crlgen.setIssuerDN(cacert.getSubjectX500Principal());
        }
        if (certs != null) {            
            Iterator it = certs.iterator();
            while( it.hasNext() ) {
                RevokedCertInfo certinfo = (RevokedCertInfo)it.next();
                crlgen.addCRLEntry(certinfo.getUserCertificate(), certinfo.getRevocationDate(), certinfo.getReason());
            }
        }

        // Authority key identifier
        if (getUseAuthorityKeyIdentifier() == true) {
            SubjectPublicKeyInfo apki = new SubjectPublicKeyInfo((ASN1Sequence)new ASN1InputStream(
                new ByteArrayInputStream(getCAToken().getPublicKey(SecConst.CAKEYPURPOSE_CRLSIGN).getEncoded())).readObject());
            AuthorityKeyIdentifier aki = new AuthorityKeyIdentifier(apki);
            crlgen.addExtension(X509Extensions.AuthorityKeyIdentifier.getId(), getAuthorityKeyIdentifierCritical(), aki);
        }
        // CRLNumber extension
        if (getUseCRLNumber() == true) {
            CRLNumber crlnum = new CRLNumber(BigInteger.valueOf(crlnumber));
            crlgen.addExtension(X509Extensions.CRLNumber.getId(),  this.getCRLNumberCritical(), crlnum);
        }

        if (isDeltaCRL) {
        	// DeltaCRLIndicator extension
        	CRLNumber basecrlnum = new CRLNumber(BigInteger.valueOf(basecrlnumber));
        	crlgen.addExtension(X509Extensions.DeltaCRLIndicator.getId(), true, basecrlnum);        	
        }
    	// CRL Distribution point URI and Freshest CRL DP
  	    if(getUseCrlDistributionPointOnCrl()) {
  	        String crldistpoint = getDefaultCRLDistPoint();
  	        List distpoints = generateDistributionPoints(crldistpoint);

  	        if (distpoints.size() > 0) {
  	            IssuingDistributionPoint idp =
  	                new IssuingDistributionPoint(((DistributionPoint) distpoints.get(0)).getDistributionPoint(),
  	                                             false, false, null, false, false);

  	            // According to the RFC, IDP must be a critical extension.
  	            // Nonetheless, at the moment, Mozilla is not able to correctly
  	            // handle the IDP extension and discards the CRL if it is critical.
  	            crlgen.addExtension(X509Extensions.IssuingDistributionPoint.getId(),
  	                                getCrlDistributionPointOnCrlCritical(), idp);
  	        }

            if (!isDeltaCRL) {
                String crlFreshestDP = getCADefinedFreshestCRL();
                List freshestDistPoints = generateDistributionPoints(crlFreshestDP);
                if (freshestDistPoints.size() > 0) {
                    CRLDistPoint ext = new CRLDistPoint((DistributionPoint[])freshestDistPoints.toArray(new DistributionPoint[0]));

                    // According to the RFC, the Freshest CRL extension on a
                    // CRL must not be marked as critical. Therefore it is
                    // hardcoded as not critical and is independent of
                    // getCrlDistributionPointOnCrlCritical().
                    crlgen.addExtension(X509Extensions.FreshestCRL.getId(),
                                        false, ext);
                }

            }
    	}

        X509CRL crl;
        crl = crlgen.generate(getCAToken().getPrivateKey(SecConst.CAKEYPURPOSE_CRLSIGN),getCAToken().getProvider());
        // Verify before sending back
        crl.verify(getCAToken().getPublicKey(SecConst.CAKEYPURPOSE_CRLSIGN));

        return crl;        
    }    

    /** Generate a list of Distribution points.
     * @param distPoints distribution points as String in semi column (';') separated format.
     * @return list of distribution points.
     */
    private List generateDistributionPoints(String distPoints) {
    	if (distPoints == null) {
    		distPoints = "";
    	}
        // Multiple CDPs are spearated with the ';' sign
    	Iterator/*String*/ it = StringTools.splitURIs(distPoints).iterator();
    	ArrayList result = new ArrayList();
        while (it.hasNext()) {
            String uri = (String) it.next();
            GeneralName gn = new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String(uri));
            if(log.isDebugEnabled()) {
                log.debug("Added CRL distpoint: " + uri);
            }
            ASN1EncodableVector vec = new ASN1EncodableVector();
            vec.add(gn);
            GeneralNames gns = new GeneralNames(new DERSequence(vec));
            DistributionPointName dpn = new DistributionPointName(0, gns);
            result.add(new DistributionPoint(dpn, null, null));
        }
        return result;
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
            log.info("Upgrading X509CA with version "+getVersion());
            if (data.get(DEFAULTOCSPSERVICELOCATOR) == null) {
                setDefaultCRLDistPoint("");
                setDefaultOCSPServiceLocator("");
            }
            if (data.get(CRLISSUEINTERVAL) == null) {
                setCRLIssueInterval(0);
            }
            if (data.get(CRLOVERLAPTIME) == null) {
            	// Default value 10 minutes
            	setCRLOverlapTime(10);
            }
            boolean useprintablestring = true;
            if (data.get("alwaysuseutf8subjectdn") == null) {
            	// Default value false
                if (data.get(USEUTF8POLICYTEXT) == null) {
                	setUseUTF8PolicyText(false);
                }
            } else {
            	// Use the same value as we had before when we had alwaysuseutf8subjectdn
                boolean useutf8 = ((Boolean)data.get("alwaysuseutf8subjectdn")).booleanValue();
                if (data.get(USEUTF8POLICYTEXT) == null) {
                	setUseUTF8PolicyText(useutf8);                	
                }
            	// If we had checked to use utf8 on an old CA, we do not want to use PrintableString after upgrading
            	useprintablestring = !useutf8;
            }
            if (data.get(USEPRINTABLESTRINGSUBJECTDN) == null) {
            	// Default value true (as before)
            	setUsePrintableStringSubjectDN(useprintablestring);
            }
            if (data.get(DEFAULTCRLISSUER) == null) {
            	setDefaultCRLIssuer(null);
            }
            if (data.get(USELDAPDNORDER) == null) {
            	if (DnComponents.isReverseOrder()) {
            		setUseLdapDNOrder(false);
            	} else {
                	setUseLdapDNOrder(true);            		
            	}
            }            
            if (data.get(DELTACRLPERIOD) == null) {
            	setDeltaCRLPeriod(0); // v14
            }
            if (data.get(USECRLDISTRIBUTIONPOINTONCRL) == null) {
                setUseCrlDistributionPointOnCrl(false); // v15
            }
            if (data.get(CRLDISTRIBUTIONPOINTONCRLCRITICAL) == null) {
                setCrlDistributionPointOnCrlCritical(false); // v15
            }
            if (data.get(INCLUDEINHEALTHCHECK) == null) {
                setIncludeInHealthCheck(true); // v16
            }
            // v17->v18 is only an upgrade in order to upgrade CA token
            // v18->v19
            Object o = data.get(CRLPERIOD);
            if (o instanceof Integer) {
            	setCRLPeriod(((Integer) o).longValue()*SimpleTime.MILLISECONDS_PER_HOUR);	// h to ms
            }
            o = data.get(CRLISSUEINTERVAL);
            if (o instanceof Integer) {
            	setCRLIssueInterval(((Integer) o).longValue()*SimpleTime.MILLISECONDS_PER_HOUR);	// h to ms
            }
            o = data.get(CRLOVERLAPTIME);
            if (o instanceof Integer) {
            	setCRLOverlapTime(((Integer) o).longValue()*SimpleTime.MILLISECONDS_PER_MINUTE);	// min to ms
            }
            o = data.get(DELTACRLPERIOD);
            if (o instanceof Integer) {
            	setDeltaCRLPeriod(((Integer) o).longValue()*SimpleTime.MILLISECONDS_PER_HOUR);	// h to ms
            }
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
    	boolean retval = false;
    	Collection extendedServiceTypes = getExternalCAServiceTypes();

    	if(getCAInfo().getStatus() != SecConst.CA_EXTERNAL){
    		// Create XKMS service if it does not exist
    		if (!extendedServiceTypes.contains(new Integer(ExtendedCAServiceInfo.TYPE_XKMSEXTENDEDSERVICE))){

    			String keytype = CATokenConstants.KEYALGORITHM_RSA;
    			String keyspec = "2048";

    			XKMSCAServiceInfo xKMSCAInfo =  new XKMSCAServiceInfo(ExtendedCAServiceInfo.STATUS_INACTIVE,
    					"CN=XKMSCertificate, " + getSubjectDN(),
    					"",
    					keyspec,
    					keytype);

    			XKMSCAService xkmsservice = new XKMSCAService(xKMSCAInfo);
    			try {
    				xkmsservice.init(this);
    				retval = true;
    			} catch (Exception e) {
    				CAInfo info = this.getCAInfo();
    				String caname = null;
    				if (info != null) {
    					caname = info.getName();
    				}
    				log.error(intres.getLocalizedMessage("signsession.errorupgradingxkmsservice",caname), e);
    			}
    			setExtendedCAService(xkmsservice);
    			extendedServiceTypes.add(new Integer(ExtendedCAServiceInfo.TYPE_XKMSEXTENDEDSERVICE));
    			data.put(EXTENDEDCASERVICES, extendedServiceTypes);
    		}		

    		// Create CMS service if it does not exist
    		if (!extendedServiceTypes.contains(new Integer(ExtendedCAServiceInfo.TYPE_CMSEXTENDEDSERVICE))){

    			String keytype = CATokenConstants.KEYALGORITHM_RSA;
    			String keyspec = "2048";

    			CmsCAServiceInfo cmsCAInfo =  new CmsCAServiceInfo(ExtendedCAServiceInfo.STATUS_INACTIVE,
    					"CN=CMSCertificate, " + getSubjectDN(),
    					"",
    					keyspec,
    					keytype);

    			CmsCAService cmsservice = new CmsCAService(cmsCAInfo);
    			try {
    				cmsservice.init(this);
    				retval = true;
    			} catch (Exception e) {
    				CAInfo info = this.getCAInfo();
    				String caname = null;
    				if (info != null) {
    					caname = info.getName();
    				}
    				log.error(intres.getLocalizedMessage("signsession.errorupgradingcmsservice",caname), e);
    			}
    			setExtendedCAService(cmsservice);
    			extendedServiceTypes.add(new Integer(ExtendedCAServiceInfo.TYPE_CMSEXTENDEDSERVICE));
    			data.put(EXTENDEDCASERVICES, extendedServiceTypes);
    		}		
    	}
    	return retval;
    }
	    
    public byte[] encryptKeys(KeyPair keypair) throws IOException, CATokenOfflineException{    
    	ByteArrayOutputStream baos = new ByteArrayOutputStream();
    	ObjectOutputStream os = new ObjectOutputStream(baos);
    	os.writeObject(keypair);    	    
    	
    	CertTools.installBCProvider();
    		
        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();    	    	    	    	      
       
    	CMSEnvelopedData ed;
		try {
			edGen.addKeyTransRecipient( this.getCAToken().getPublicKey(SecConst.CAKEYPURPOSE_KEYENCRYPT), this.keyId);
			ed = edGen.generate(
					new CMSProcessableByteArray(baos.toByteArray()), CMSEnvelopedDataGenerator.AES256_CBC,"BC");
		} catch (Exception e) {
            log.error("-encryptKeys: ", e);
            throw new IOException(e.getMessage());        
		}
				
		
		return ed.getEncoded(); 
    }
    
    public KeyPair decryptKeys(byte[] data) throws Exception {
    	CMSEnvelopedData ed = new CMSEnvelopedData(data);   	    	
    	     
		RecipientInformationStore  recipients = ed.getRecipientInfos();           	
    	Iterator    it =  recipients.getRecipients().iterator();
    	RecipientInformation   recipient = (RecipientInformation) it.next();
    	ObjectInputStream ois = null;
    	byte[] recdata = recipient.getContent(getCAToken().getPrivateKey(SecConst.CAKEYPURPOSE_KEYENCRYPT),getCAToken().getJCEProvider());
    	ois = new ObjectInputStream(new ByteArrayInputStream(recdata));
    	    	    	
    	return (KeyPair) ois.readObject();  
    }

	public byte[] decryptData(byte[] data, int cAKeyPurpose) throws Exception {
    	CMSEnvelopedData ed = new CMSEnvelopedData(data);
		RecipientInformationStore  recipients = ed.getRecipientInfos();           	
    	Iterator    it =  recipients.getRecipients().iterator();
    	RecipientInformation   recipient = (RecipientInformation) it.next();
    	byte[] recdata = recipient.getContent(getCAToken().getPrivateKey(cAKeyPurpose),getCAToken().getProvider());    	
    	    	    	
    	return recdata;  
	}

	public byte[] encryptData(byte[] data, int keyPurpose) throws Exception {
    	CertTools.installBCProvider();
        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();    	    	    	    	             
    	CMSEnvelopedData ed;
		try {
			edGen.addKeyTransRecipient( this.getCAToken().getPublicKey(keyPurpose), this.keyId);
			ed = edGen.generate(
					new CMSProcessableByteArray(data), CMSEnvelopedDataGenerator.AES256_CBC,"BC");
		} catch (Exception e) {
            log.error("-encryptKeys: ", e);
            throw new IOException(e.getMessage());        
		}				
		
		return ed.getEncoded(); 
	}
    
}

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
import java.security.KeyPair;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CRL;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.StringTokenizer;
import java.util.Vector;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEREncodableVector;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.asn1.x509.qualified.QCStatement;
import org.bouncycastle.asn1.x509.qualified.RFC3739QCObjectIdentifiers;
import org.bouncycastle.asn1.x509.qualified.SemanticsInformation;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.ocsp.BasicOCSPRespGenerator;
import org.bouncycastle.ocsp.OCSPException;
import org.ejbca.core.ejb.ca.caadmin.CADataBean;
import org.ejbca.core.ejb.ca.sign.SernoGenerator;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ca.SignRequestSignatureException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceNotActiveException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceRequest;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceRequestException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceResponse;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.IllegalExtendedCAServiceRequestException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.OCSPCAServiceRequest;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.OCSPCAServiceResponse;
import org.ejbca.core.model.ca.catoken.CATokenOfflineException;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfile;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.util.CertTools;

import se.anatom.ejbca.common.UserDataVO;



/**
 * X509CA is a implementation of a CA and holds data specific for Certificate and CRL generation 
 * according to the X509 standard. 
 *
 * @version $Id: X509CA.java,v 1.1 2006-01-17 20:28:05 anatom Exp $
 */
public class X509CA extends CA implements Serializable {

    private static final Logger log = Logger.getLogger(X509CA.class);

    // Default Values
    public static final float LATEST_VERSION = 2;

    private byte[]  keyId = new byte[] { 1, 2, 3, 4, 5 };
    
    
    // protected fields.
    protected static final String POLICYID                       = "policyid";
    protected static final String SUBJECTALTNAME                 = "subjectaltname";
    protected static final String USEAUTHORITYKEYIDENTIFIER      = "useauthoritykeyidentifier";
    protected static final String AUTHORITYKEYIDENTIFIERCRITICAL = "authoritykeyidentifiercritical";
    protected static final String USECRLNUMBER                   = "usecrlnumber";
    protected static final String CRLNUMBERCRITICAL              = "crlnumbercritical";
    protected static final String DEFAULTCRLDISTPOINT            = "defaultcrldistpoint";
    protected static final String DEFAULTOCSPSERVICELOCATOR      = "defaultocspservicelocator";

    /** OID used for creating MS Templates */
    protected static final String OID_MSTEMPLATE = "1.3.6.1.4.1.311.20.2";
      
    // Public Methods
    /** Creates a new instance of CA, this constuctor should be used when a new CA is created */
    public X509CA(X509CAInfo cainfo) {
      super(cainfo);  
      
      data.put(POLICYID, cainfo.getPolicyId());
      data.put(SUBJECTALTNAME,  cainfo.getSubjectAltName());            
      setUseAuthorityKeyIdentifier(cainfo.getUseAuthorityKeyIdentifier());
      setAuthorityKeyIdentifierCritical(cainfo.getAuthorityKeyIdentifierCritical()); 
      setUseCRLNumber(cainfo.getUseCRLNumber());
      setCRLNumberCritical(cainfo.getCRLNumberCritical());
      setDefaultCRLDistPoint(cainfo.getDefaultCRLDistPoint());
      setDefaultOCSPServiceLocator(cainfo.getDefaultOCSPServiceLocator());
      setFinishUser(cainfo.getFinishUser());
      
      data.put(CA.CATYPE, new Integer(CAInfo.CATYPE_X509));
      data.put(VERSION, new Float(LATEST_VERSION));      
    }
    
   /** Constructor used when retrieving existing X509CA from database. */
    public X509CA(HashMap data, CADataBean owner){
      super(data, owner);
    }

    // Public Methods.
    public String getPolicyId(){ return (String) data.get(POLICYID);}
    public void setPolicyId(String policyid){ data.put(POLICYID, policyid);}
    
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
    public void setDefaultCRLDistPoint(String defailtcrldistpoint) {
    	if(defailtcrldistpoint == null){
    		data.put(DEFAULTCRLDISTPOINT, "");
    	}else{
    		data.put(DEFAULTCRLDISTPOINT, defailtcrldistpoint);
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
    
    
    public void updateCA(CAInfo cainfo) throws Exception{
      super.updateCA(cainfo); 
      X509CAInfo info = (X509CAInfo) cainfo;

      setUseAuthorityKeyIdentifier(info.getUseAuthorityKeyIdentifier());
      setAuthorityKeyIdentifierCritical(info.getAuthorityKeyIdentifierCritical()); 
      setUseCRLNumber(info.getUseCRLNumber());
      setCRLNumberCritical(info.getCRLNumberCritical());
      setDefaultCRLDistPoint(info.getDefaultCRLDistPoint());
      setDefaultOCSPServiceLocator(info.getDefaultOCSPServiceLocator());
    }
    
    public CAInfo getCAInfo() throws Exception{
      ArrayList externalcaserviceinfos = new ArrayList();
      Iterator iter = getExternalCAServiceTypes().iterator(); 	
      while(iter.hasNext()){
      	externalcaserviceinfos.add(this.getExtendedCAServiceInfo(((Integer) iter.next()).intValue()));  	
      }
    	                
      return new X509CAInfo(getSubjectDN(), getName(), getStatus(), getSubjectAltName() ,getCertificateProfileId(),  
                    getValidity(), getExpireTime(), getCAType(), getSignedBy(), getCertificateChain(),
                    getCAToken().getCATokenInfo(), getDescription(), getRevokationReason(), getRevokationDate(), getPolicyId(), getCRLPeriod(), getCRLPublishers(),
                    getUseAuthorityKeyIdentifier(), getAuthorityKeyIdentifierCritical(),
                    getUseCRLNumber(), getCRLNumberCritical(), getDefaultCRLDistPoint(), getDefaultOCSPServiceLocator(), getFinishUser(), externalcaserviceinfos); 
    }


    public byte[] createPKCS7(Certificate cert, boolean includeChain) throws SignRequestSignatureException {
        // First verify that we signed this certificate
        try {
            if (cert != null)
                cert.verify(getCAToken().getPublicKey(SecConst.CAKEYPURPOSE_CERTSIGN), getCAToken().getProvider());
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
            gen.addSigner(getCAToken().getPrivateKey(SecConst.CAKEYPURPOSE_CERTSIGN), (X509Certificate)getCACertificate(), CMSSignedDataGenerator.DIGEST_SHA1);
            gen.addCertificatesAndCRLs(certs);
            CMSSignedData s = gen.generate(msg, true, getCAToken().getProvider());
            return s.getEncoded();
        } catch (CATokenOfflineException e) {
        	this.setStatus(SecConst.CA_OFFLINE);
        	throw new javax.ejb.EJBException(e);        	
        } catch (Exception e) {
            throw new javax.ejb.EJBException(e);
        }   
    }    
    
    
    public Certificate generateCertificate(UserDataVO subject, 
                                           PublicKey publicKey, 
                                           int keyusage, 
                                           long validity,
                                           CertificateProfile certProfile) throws Exception{
                                               
    	    	
        final String sigAlg = getCAToken().getCATokenInfo().getSignatureAlgorithm();
        Date firstDate = new Date();
        // Set back startdate ten minutes to avoid some problems with wrongly set clocks.
        firstDate.setTime(firstDate.getTime() - 10 * 60 * 1000);
        Date lastDate = new Date();
        // validity in days = validity*24*60*60*1000 milliseconds
        long val = validity;
        if(val == -1)
          val = certProfile.getValidity();
        
        lastDate.setTime(lastDate.getTime() + ( val * 24 * 60 * 60 * 1000));
        ExtendedX509V3CertificateGenerator certgen = new ExtendedX509V3CertificateGenerator();
        // Serialnumber is random bits, where random generator is initialized by the
        // serno generator.
        BigInteger serno = SernoGenerator.instance().getSerno();
        certgen.setSerialNumber(serno);
        certgen.setNotBefore(firstDate);
        certgen.setNotAfter(lastDate);
        certgen.setSignatureAlgorithm(sigAlg);
        // Make DNs
        String dn = subject.getDN(); 
        
        if(certProfile.getUseSubjectDNSubSet()){
          dn= certProfile.createSubjectDNSubSet(dn);	
        }
        
        if(certProfile.getUseCNPostfix()){
          dn = CertTools.insertCNPostfix(dn,certProfile.getCNPostfix());	
        }
        
        
        String altName = subject.getSubjectAltName(); 
      
        if(certProfile.getUseSubjectAltNameSubSet()){
        	altName = certProfile.createSubjectAltNameSubSet(altName);
        }
        
        certgen.setSubjectDN(CertTools.stringToBcX509Name(dn));
        // We must take the issuer DN directly from the CA-certificate otherwise we risk re-ordering the DN
        // which many applications do not like.
        X509Certificate cacert = (X509Certificate)getCACertificate();
        if (cacert == null) {
        	// This will be an initial root CA, since no CA-certificate exists
            X509Name caname = CertTools.stringToBcX509Name(getSubjectDN());
            certgen.setIssuerDN(caname);
        } else {
            certgen.setIssuerDN(cacert.getSubjectX500Principal());        	
        }
        certgen.setPublicKey(publicKey);

        // Basic constranits, all subcerts are NOT CAs
        if (certProfile.getUseBasicConstraints() == true) {
        	BasicConstraints bc = new BasicConstraints(false);
            if ((certProfile.getType() == CertificateProfile.TYPE_SUBCA)
                || (certProfile.getType() == CertificateProfile.TYPE_ROOTCA)){            	
            	if(certProfile.getUsePathLengthConstraint()){
            		bc = new BasicConstraints(certProfile.getPathLengthConstraint());
            	}else{
            		bc =  new BasicConstraints(true);
            	}            	
            }
                            
            certgen.addExtension(
                X509Extensions.BasicConstraints.getId(),
                certProfile.getBasicConstraintsCritical(),
                bc);
        }
        // Key usage
        int newKeyUsage = -1;
        if (certProfile.getAllowKeyUsageOverride() && (keyusage >= 0)) {
            newKeyUsage = keyusage;
        } else {
            newKeyUsage = CertTools.sunKeyUsageToBC(certProfile.getKeyUsage());
        }
        if ( (certProfile.getUseKeyUsage() == true) && (newKeyUsage >=0) ){
            X509KeyUsage ku = new X509KeyUsage(newKeyUsage);
            certgen.addExtension(
                X509Extensions.KeyUsage.getId(),
                certProfile.getKeyUsageCritical(),
                ku);
        }
        // Extended Key usage
        if (certProfile.getUseExtendedKeyUsage() == true) {
            // Get extended key usage from certificate profile
            Collection c = certProfile.getExtendedKeyUsageAsOIDStrings();
            Vector usage = new Vector();
            Iterator iter = c.iterator();
            while (iter.hasNext()) {
                usage.add(new DERObjectIdentifier((String)iter.next()));
            }
            ExtendedKeyUsage eku = new ExtendedKeyUsage(usage);
            // Extended Key Usage may be either critical or non-critical
            certgen.addExtension(
                X509Extensions.ExtendedKeyUsage.getId(),
                certProfile.getExtendedKeyUsageCritical(),
                eku);
        }
        // Subject key identifier
        if (certProfile.getUseSubjectKeyIdentifier() == true) {
            SubjectPublicKeyInfo spki =
                new SubjectPublicKeyInfo(
                    (ASN1Sequence) new ASN1InputStream(new ByteArrayInputStream(publicKey.getEncoded())).readObject());
            SubjectKeyIdentifier ski = new SubjectKeyIdentifier(spki);
            certgen.addExtension(
                X509Extensions.SubjectKeyIdentifier.getId(),
                certProfile.getSubjectKeyIdentifierCritical(), ski);
        }
        // Authority key identifier
        if (certProfile.getUseAuthorityKeyIdentifier() == true) {
            SubjectPublicKeyInfo apki = null;
            try{
              apki =
                new SubjectPublicKeyInfo(
                    (ASN1Sequence) new ASN1InputStream(new ByteArrayInputStream(getCAToken().getPublicKey(SecConst.CAKEYPURPOSE_CERTSIGN).getEncoded())).readObject());
             }catch(CATokenOfflineException e){
                 log.debug("X509CA : Setting STATUS OFFLINE " + this.getName());    
                 this.setStatus(SecConst.CA_OFFLINE);
                 log.debug("X509CA : New STATUS  " + this.getStatus());
                 throw new CATokenOfflineException(e.getMessage()); 
            }
            AuthorityKeyIdentifier aki = new AuthorityKeyIdentifier(apki);
            certgen.addExtension(
                X509Extensions.AuthorityKeyIdentifier.getId(),
                certProfile.getAuthorityKeyIdentifierCritical(), aki);
        }
         // Subject Alternative name
        if ( (certProfile.getUseSubjectAlternativeName() == true) && (altName != null) && (altName.length() > 0) ) {
            GeneralNames san = CertTools.getGeneralNamesFromAltName(altName);            
            if (san != null) {
                certgen.addExtension(X509Extensions.SubjectAlternativeName.getId(), certProfile.getSubjectAlternativeNameCritical(), san);
            }
        }
        
        // Certificate Policies
         if (certProfile.getUseCertificatePolicies() == true) {
                 PolicyInformation pi = new PolicyInformation(new DERObjectIdentifier(certProfile.getCertificatePolicyId()));
                 DERSequence seq = new DERSequence(pi);
                 certgen.addExtension(X509Extensions.CertificatePolicies.getId(),
                         certProfile.getCertificatePoliciesCritical(), seq);
         }

         // CRL Distribution point URI
         if (certProfile.getUseCRLDistributionPoint() == true) {
        	 String crldistpoint = certProfile.getCRLDistributionPointURI();
        	 if(certProfile.getUseDefaultCRLDistributionPoint()){
        		 crldistpoint = getDefaultCRLDistPoint();
        	 }
             // Multiple CDPs are spearated with the ';' sign        	         	 
            StringTokenizer tokenizer = new StringTokenizer(crldistpoint, ";", false);
            ArrayList distpoints = new ArrayList();
            while (tokenizer.hasMoreTokens()) {
                // 6 is URI
                String uri = tokenizer.nextToken();
                GeneralName gn = new GeneralName(6, new DERIA5String(uri));
                log.debug("Added CRL distpoint: "+uri);
                ASN1EncodableVector vec = new ASN1EncodableVector();
                vec.add(gn);
                GeneralNames gns = new GeneralNames(new DERSequence(vec));
                DistributionPointName dpn = new DistributionPointName(0, gns);
                distpoints.add(new DistributionPoint(dpn, null, null));
            }
            if (distpoints.size() > 0) {
                CRLDistPoint ext = new CRLDistPoint((DistributionPoint[])distpoints.toArray(new DistributionPoint[0]));
                certgen.addExtension(X509Extensions.CRLDistributionPoints.getId(),
                    certProfile.getCRLDistributionPointCritical(), ext);
            }
         }
         // Authority Information Access (OCSP url)
         if (certProfile.getUseOCSPServiceLocator() == true) {
             String ocspUrl = certProfile.getOCSPServiceLocatorURI();
             if(certProfile.getUseDefaultOCSPServiceLocator()){
            	 ocspUrl = getDefaultOCSPServiceLocator();
             }
             // OCSP access location is a URL (GeneralName no 6)
             GeneralName ocspLocation = new GeneralName(6, new DERIA5String(ocspUrl));
             certgen.addExtension(X509Extensions.AuthorityInfoAccess.getId(),
                 false, new AuthorityInformationAccess(X509ObjectIdentifiers.ocspAccessMethod, ocspLocation));
         }
         
         // Microsoft Template
         if (certProfile.getUseMicrosoftTemplate() == true) {
             String mstemplate = certProfile.getMicrosoftTemplate();             
             DERObjectIdentifier oid = new DERObjectIdentifier(OID_MSTEMPLATE);                           
             certgen.addExtension(oid, false, new DERIA5String(mstemplate));             
         }
         
         // QCStatement (rfc3739)
         if (certProfile.getUseQCStatement() == true) {
             String names = certProfile.getQCStatementRAName();
             GeneralNames san = CertTools.getGeneralNamesFromAltName(names);
             SemanticsInformation si = null;
             if (san != null) {
                 if (StringUtils.isNotEmpty(certProfile.getQCSemanticsId())) {
                     si = new SemanticsInformation(new DERObjectIdentifier(certProfile.getQCSemanticsId()), san.getNames());
                 } else {
                     si = new SemanticsInformation(san.getNames());                     
                 }
             } else if (StringUtils.isNotEmpty(certProfile.getQCSemanticsId())) {
                 si = new SemanticsInformation(new DERObjectIdentifier(certProfile.getQCSemanticsId()));                 
             }
             QCStatement qc = null;
             if ( (si != null)  ) {
                 qc = new QCStatement(RFC3739QCObjectIdentifiers.id_qcs_pkixQCSyntax_v2, si);
             } 
             if (qc != null) {
                 // we only support one QCStatement in the sequence of QCStatements                 
                 DEREncodableVector vec = new DEREncodableVector();
                 vec.add(qc);
                 certgen.addExtension(CertTools.QCSTATEMENTS_OBJECTID, certProfile.getQCStatementCritical(), new DERSequence(vec));                 
             }
         }
		          
         X509Certificate cert;
         try{
           cert = certgen.generateX509Certificate(getCAToken().getPrivateKey(SecConst.CAKEYPURPOSE_CERTSIGN), 
                                            getCAToken().getProvider());
         }catch(CATokenOfflineException e){
             log.debug("X509CA : Setting STATUS OFFLINE");
             this.setStatus(SecConst.CA_OFFLINE);
             throw e; 
         }
        
        // Verify before returning
        cert.verify(getCAToken().getPublicKey(SecConst.CAKEYPURPOSE_CERTSIGN));
        log.debug(">X509CA: generate certificate, CA "+ this.getCAId() + " for DN=" + subject.getDN());
            
      return cert;                                                                                        
    }

    
    public CRL generateCRL(Vector certs, int crlnumber) throws Exception {
        final String sigAlg= getCAToken().getCATokenInfo().getSignatureAlgorithm();

        Date thisUpdate = new Date();
        Date nextUpdate = new Date();

        // crlperiod is hours = crlperiod*60*60*1000 milliseconds
        nextUpdate.setTime(nextUpdate.getTime() + (getCRLPeriod() * (long)(60 * 60 * 1000)));
        ExtendedX509V2CRLGenerator crlgen = new ExtendedX509V2CRLGenerator();
        crlgen.setThisUpdate(thisUpdate);
        crlgen.setNextUpdate(nextUpdate);
        crlgen.setSignatureAlgorithm(sigAlg);
        // Make DNs
        X509Name caname = new X509Name(getSubjectDN());
        crlgen.setIssuerDN(caname);
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
        
        X509CRL crl;
        try{
        	crl = crlgen.generateX509CRL(getCAToken().getPrivateKey(SecConst.CAKEYPURPOSE_CRLSIGN),getCAToken().getProvider());
        }catch(CATokenOfflineException e){
        	this.setStatus(SecConst.CA_OFFLINE);
        	throw e; 
        }                        
        // Verify before sending back
        crl.verify(getCAToken().getPublicKey(SecConst.CAKEYPURPOSE_CRLSIGN));

        return crl;        
    }    
    
    /** Implemtation of UpgradableDataHashMap function getLatestVersion */
    public float getLatestVersion(){
       return LATEST_VERSION;
    }

    /** Implemtation of UpgradableDataHashMap function upgrade. */

    public void upgrade(){
      if(LATEST_VERSION != getVersion()){
        // New version of the class, upgrade
    	  
    	  if(data.get(DEFAULTOCSPSERVICELOCATOR) == null){
    		  setDefaultCRLDistPoint("");
    		  setDefaultOCSPServiceLocator("");
    	  }

        data.put(VERSION, new Float(LATEST_VERSION));
      }  
    }

    /** 
     * Method used to perform an extended service.
     */
    public ExtendedCAServiceResponse extendedService(ExtendedCAServiceRequest request) 
      throws ExtendedCAServiceRequestException, IllegalExtendedCAServiceRequestException, ExtendedCAServiceNotActiveException{
          log.debug(">extendedService()");
          ExtendedCAServiceResponse returnval = null; 
          if(request instanceof OCSPCAServiceRequest) {
              BasicOCSPRespGenerator ocsprespgen = ((OCSPCAServiceRequest)request).getOCSPrespGenerator();
              String sigAlg = ((OCSPCAServiceRequest)request).getSigAlg();
              boolean useCACert = ((OCSPCAServiceRequest)request).useCACert();
              boolean includeChain = ((OCSPCAServiceRequest)request).includeChain();
              PrivateKey pk = null;
              X509Certificate[] chain = null;
              try {
                  if (useCACert) {
                      pk = getCAToken().getPrivateKey(SecConst.CAKEYPURPOSE_CERTSIGN);
                      if (includeChain) {
                          chain = (X509Certificate[])getCertificateChain().toArray(new X509Certificate[0]);
                      } 
                  } else {
                      // Super class handles signing with the OCSP signing certificate
                      log.debug("<extendedService(super)");
                      return super.extendedService(request);                      
                  }
                  BasicOCSPResp ocspresp = ocsprespgen.generate(sigAlg, pk, chain, new Date(), getCAToken().getProvider() );
                  returnval = new OCSPCAServiceResponse(ocspresp, chain == null ? null : Arrays.asList(chain));              
              } catch (IllegalKeyStoreException ike) {
                  throw new ExtendedCAServiceRequestException(ike);
              } catch (NoSuchProviderException nspe) {
                  throw new ExtendedCAServiceRequestException(nspe);
              } catch (OCSPException ocspe) {
                  throw new ExtendedCAServiceRequestException(ocspe);                  
              } catch (CATokenOfflineException ctoe) {
              	this.setStatus(SecConst.CA_OFFLINE);
              	throw new ExtendedCAServiceRequestException(ctoe);
			}
          } else {
              log.debug("<extendedService(super)");
              return super.extendedService(request);
          }
          log.debug("<extendedService()");
          return returnval;
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
		} catch (CATokenOfflineException ctoe) {
			this.setStatus(SecConst.CA_OFFLINE);
          	throw ctoe;	 	
		} catch (Exception e) {
            setStatus(SecConst.CA_OFFLINE);
            log.error("-encryptKeys: ", e);
            throw new IOException(e.getMessage());        
		}
				
		
		return ed.getEncoded(); 
    }
    
    public KeyPair decryptKeys(byte[] data) throws Exception{
    	CMSEnvelopedData ed = new CMSEnvelopedData(data);   	    	
    	     
		RecipientInformationStore  recipients = ed.getRecipientInfos();           	
    	Iterator    it =  recipients.getRecipients().iterator();
    	RecipientInformation   recipient = (RecipientInformation) it.next();
    	ObjectInputStream ois = null;
    	try{
    	  byte[] recdata = recipient.getContent(getCAToken().getPrivateKey(SecConst.CAKEYPURPOSE_KEYENCRYPT),getCAToken().getProvider());
    	  ois = new ObjectInputStream(new ByteArrayInputStream(recdata));
    	}catch(CATokenOfflineException e){
    		setStatus(SecConst.CA_OFFLINE);
    		throw e;
    	}
    	    	    	
    	return (KeyPair) ois.readObject();  
    }
    
    
}

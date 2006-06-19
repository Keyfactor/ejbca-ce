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
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CRL;
import java.security.cert.CRLException;
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
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x509.Attribute;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.DisplayText;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.PolicyQualifierId;
import org.bouncycastle.asn1.x509.PolicyQualifierInfo;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.UserNotice;
import org.bouncycastle.asn1.x509.X509DefaultEntryConverter;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.asn1.x509.X509NameEntryConverter;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.asn1.x509.qualified.ETSIQCObjectIdentifiers;
import org.bouncycastle.asn1.x509.qualified.Iso4217CurrencyCode;
import org.bouncycastle.asn1.x509.qualified.MonetaryValue;
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
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.util.CertTools;
import org.ejbca.util.cert.SubjectDirAttrExtension;
import org.ejbca.util.cert.UTF8EntryConverter;




/**
 * X509CA is a implementation of a CA and holds data specific for Certificate and CRL generation 
 * according to the X509 standard. 
 *
 * @version $Id: X509CA.java,v 1.20 2006-06-19 14:06:17 anatom Exp $
 */
public class X509CA extends CA implements Serializable {

    private static final Logger log = Logger.getLogger(X509CA.class);

    // Default Values
    public static final float LATEST_VERSION = 5;

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
    protected static final String ALWAYSUSEUTF8SUBJECTDN         = "alwaysuseutf8subjectdn";

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
      setAlwaysUseUTF8SubjectDN(cainfo.getAlwaysUseUTF8SubjectDN());
      
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

    public boolean  getAlwaysUseUTF8SubjectDN(){
        return ((Boolean)data.get(ALWAYSUSEUTF8SUBJECTDN)).booleanValue();
      }
      public void setAlwaysUseUTF8SubjectDN(boolean alwaysuseutf8) {
        data.put(ALWAYSUSEUTF8SUBJECTDN, Boolean.valueOf(alwaysuseutf8));
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
      setAlwaysUseUTF8SubjectDN(info.getAlwaysUseUTF8SubjectDN());
    }
    
    public CAInfo getCAInfo() throws Exception{
      ArrayList externalcaserviceinfos = new ArrayList();
      Iterator iter = getExternalCAServiceTypes().iterator(); 	
      while(iter.hasNext()){
      	externalcaserviceinfos.add(this.getExtendedCAServiceInfo(((Integer) iter.next()).intValue()));  	
      }
    	                
      return new X509CAInfo(getSubjectDN(), getName(), getStatus(), getSubjectAltName() ,getCertificateProfileId(),  
                    getValidity(), getExpireTime(), getCAType(), getSignedBy(), getCertificateChain(),
                    getCAToken().getCATokenInfo(), getDescription(), getRevokationReason(), getRevokationDate(), getPolicyId(), getCRLPeriod(), getCRLIssueInterval(), getCRLOverlapTime(), getCRLPublishers(),
                    getUseAuthorityKeyIdentifier(), getAuthorityKeyIdentifierCritical(),
                    getUseCRLNumber(), getCRLNumberCritical(), getDefaultCRLDistPoint(), getDefaultOCSPServiceLocator(), getFinishUser(), externalcaserviceinfos, getAlwaysUseUTF8SubjectDN()); 
    }


    public byte[] createPKCS7(Certificate cert, boolean includeChain) throws SignRequestSignatureException {
        // First verify that we signed this certificate
        try {
            if (cert != null)
                cert.verify(getCAToken().getPublicKey(SecConst.CAKEYPURPOSE_CERTSIGN));
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
        X509Certificate cacert = (X509Certificate)getCACertificate();
        // If our desired after date is after the CA expires, we will not allow this
        // The CA will only issue certificates with maximum the same validity time as it-self
        if (cacert != null) {
            if (lastDate.after(cacert.getNotAfter())) {
                log.info("Limiting validity of certificate because requested validity is beyond CA validity");
                lastDate = cacert.getNotAfter();
            }            
        }
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
        
        X509NameEntryConverter converter = null;
        if (getAlwaysUseUTF8SubjectDN()) {
        	converter = new UTF8EntryConverter();
        } else {
        	converter = new X509DefaultEntryConverter();
        }
        certgen.setSubjectDN(CertTools.stringToBcX509Name(dn, converter));
        // We must take the issuer DN directly from the CA-certificate otherwise we risk re-ordering the DN
        // which many applications do not like.
        if (cacert == null) {
        	// This will be an initial root CA, since no CA-certificate exists
            X509Name caname = CertTools.stringToBcX509Name(getSubjectDN(), converter);
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
                 log.debug("X509CA: CA Token Offline Exception: ", e);                
                 throw e; 
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
            int displayencoding = DisplayText.CONTENT_TYPE_BMPSTRING;
            if (getAlwaysUseUTF8SubjectDN()) {
                displayencoding = DisplayText.CONTENT_TYPE_UTF8STRING;
            }
            PolicyInformation pi = getPolicyInformation(certProfile.getCertificatePolicyId(), certProfile.getCpsUrl(), certProfile.getUserNoticeText(), displayencoding);
            
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
             DERObjectIdentifier oid = new DERObjectIdentifier(CertTools.OID_MSTEMPLATE);                           
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
             ArrayList qcs = new ArrayList();
             QCStatement qc = null;
             // First the standard rfc3739 QCStatement with an optional SematicsInformation
             DERObjectIdentifier pkixQcSyntax = RFC3739QCObjectIdentifiers.id_qcs_pkixQCSyntax_v1;
             if (certProfile.getUsePkixQCSyntaxV2()) {
            	 pkixQcSyntax = RFC3739QCObjectIdentifiers.id_qcs_pkixQCSyntax_v2;
             }
             if ( (si != null)  ) {
                 qc = new QCStatement(pkixQcSyntax, si);
                 qcs.add(qc);
             } else {
            	 qc = new QCStatement(pkixQcSyntax);
                 qcs.add(qc);
             }
             // ETSI Statement that the certificate is a Qualified Certificate
             if (certProfile.getUseQCEtsiQCCompliance()) {
            	 qc = new QCStatement(ETSIQCObjectIdentifiers.id_etsi_qcs_QcCompliance);
                 qcs.add(qc);
             }
             // ETSI Statement regarding limit on the value of transactions
             if (certProfile.getUseQCEtsiValueLimit()) {
            	 // Both value and currency must be availabel for this extension
            	 if ( (certProfile.getQCEtsiValueLimit() > 0) && (certProfile.getQCEtsiValueLimitCurrency() != null) ) {
            		 int limit = certProfile.getQCEtsiValueLimit();
            		 // The exponent should be default 0
            		 int exponent = certProfile.getQCEtsiValueLimitExp();
            		 MonetaryValue value = new MonetaryValue(new Iso4217CurrencyCode(certProfile.getQCEtsiValueLimitCurrency()), limit, exponent);
            		 qc = new QCStatement(ETSIQCObjectIdentifiers.id_etsi_qcs_LimiteValue, value);
            		 qcs.add(qc);
            	 }
             }
             // ETSI Statement claiming that the private key resides in a Signature Creation Device
             if (certProfile.getUseQCEtsiSignatureDevice()) {
            	 qc = new QCStatement(ETSIQCObjectIdentifiers.id_etsi_qcs_QcSSCD);
                 qcs.add(qc);
             }
             // Custom UTF8String QC-statement:
 			 // qcStatement-YourCustom QC-STATEMENT ::= { SYNTAX YourCustomUTF8String
			 //   IDENTIFIED BY youroid }
			 //   -- This statement gives you the possibility to define your own QC-statement
			 //   -- using an OID and a simple UTF8String, with describing text. A sample text could for example be:
			 //   -- This certificate, according to Act. No. xxxx Electronic Signature Law is a qualified electronic certificate
			 //
			 // YourCustomUTF8String ::= UTF8String
             if (certProfile.getUseQCCustomString()) {
            	 if (!StringUtils.isEmpty(certProfile.getQCCustomStringOid()) && !StringUtils.isEmpty(certProfile.getQCCustomStringText())) {
            		 DERUTF8String str = new DERUTF8String(certProfile.getQCCustomStringText());
            		 DERObjectIdentifier oid = new DERObjectIdentifier(certProfile.getQCCustomStringOid());
                	 qc = new QCStatement(oid, str);
                     qcs.add(qc);            		 
            	 }
             }
             if (qcs.size() >  0) {
                 DEREncodableVector vec = new DEREncodableVector();
                 Iterator iter = qcs.iterator();
                 while (iter.hasNext()) {
                	 QCStatement q = (QCStatement)iter.next();
                     vec.add(q);
                 }
                 certgen.addExtension(CertTools.QCSTATEMENTS_OBJECTID, certProfile.getQCStatementCritical(), new DERSequence(vec));                 
             }
         }
         
         // Subject Directory Attributes
         if (certProfile.getUseSubjectDirAttributes() == true) {
        	 // Get the attributes from ExtendedInformation
        	 String dirAttrString = subject.getExtendedinformation().getSubjectDirectoryAttributes();
        	 if (StringUtils.isNotEmpty(dirAttrString)) {
            	 // Subject Directory Attributes is a sequence of Attribute
            	 Collection attr = SubjectDirAttrExtension.getSubjectDirectoryAttributes(dirAttrString, converter);
            	 DEREncodableVector vec = new DEREncodableVector();
            	 Iterator iter = attr.iterator();
            	 while (iter.hasNext()) {
            		 Attribute a = (Attribute)iter.next();
            		 vec.add(a);
            	 }        		 
            	 // Subject Directory Attributes must always be non-critical
            	 certgen.addExtension(X509Extensions.SubjectDirectoryAttributes, false, new DERSequence(vec));                 
        	 }
        	 
         }         
		          
         X509Certificate cert;
         try{
           cert = certgen.generateX509Certificate(getCAToken().getPrivateKey(SecConst.CAKEYPURPOSE_CERTSIGN), 
                                            getCAToken().getProvider());
         }catch(CATokenOfflineException e){
             log.debug("X509CA : CA Token STATUS OFFLINE: ", e);
             throw e; 
         }
        
        // Verify before returning
        cert.verify(getCAToken().getPublicKey(SecConst.CAKEYPURPOSE_CERTSIGN));
        log.debug(">X509CA: generate certificate, CA "+ this.getCAId() + " for DN=" + subject.getDN());
      return cert;                                                                                        
    }

    
    public CRL generateCRL(Vector certs, int crlnumber) 
    throws CATokenOfflineException, IllegalKeyStoreException, IOException, SignatureException, NoSuchProviderException, InvalidKeyException, CRLException, NoSuchAlgorithmException {
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
        crl = crlgen.generateX509CRL(getCAToken().getPrivateKey(SecConst.CAKEYPURPOSE_CRLSIGN),getCAToken().getProvider());
        // Verify before sending back
        crl.verify(getCAToken().getPublicKey(SecConst.CAKEYPURPOSE_CRLSIGN));

        return crl;        
    }    
    
    /** Implemtation of UpgradableDataHashMap function getLatestVersion */
    public float getLatestVersion(){
       return LATEST_VERSION;
    }

    /** Implemtation of UpgradableDataHashMap function upgrade. 
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
            if (data.get(ALWAYSUSEUTF8SUBJECTDN) == null) {
            	// Default value false (as before)
            	setAlwaysUseUTF8SubjectDN(false);
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
    	byte[] recdata = recipient.getContent(getCAToken().getPrivateKey(SecConst.CAKEYPURPOSE_KEYENCRYPT),getCAToken().getProvider());
    	ois = new ObjectInputStream(new ByteArrayInputStream(recdata));
    	    	    	
    	return (KeyPair) ois.readObject();  
    }
    
    
    /**
     * Obtains the Policy Notice
     * 
     * @param policyOID,
     *          OID of the policy
     * @param cps,
     *          url to cps document
     * @param unotice,
     *          user notice text
     * @param displayencoding,
     *          the encoding used for UserNotice text, DisplayText.CONTENT_TYPE_BMPSTRING, CONTENT_TYPE_UTF8STRING, CONTENT_TYPE_IA5STRING or CONTENT_TYPE_VISIBLESTRING 
     *          
     * @return
     */
    private PolicyInformation getPolicyInformation(String policyOID, String cps, String unotice, int displayencoding) {
        
        DEREncodableVector qualifiers = new DEREncodableVector();
        if (!StringUtils.isEmpty(unotice)) {
            // Normally we would just use 'DisplayText(unotice)' here. IE has problems with UTF8 though, so lets stick with BMSSTRING to satisfy Bills sick needs.
            UserNotice un = new UserNotice(null, new DisplayText(displayencoding, unotice));
            PolicyQualifierInfo pqiUNOTICE = new PolicyQualifierInfo(PolicyQualifierId.id_qt_unotice, un);
            qualifiers.add(pqiUNOTICE);
        }
        if (!StringUtils.isEmpty(cps)) {
            PolicyQualifierInfo pqiCPS = new PolicyQualifierInfo(cps);
            qualifiers.add(pqiCPS);
        }
        PolicyInformation policyInformation = new PolicyInformation(new DERObjectIdentifier(policyOID), new DERSequence(qualifiers));
        
        return policyInformation;
    }
    
}
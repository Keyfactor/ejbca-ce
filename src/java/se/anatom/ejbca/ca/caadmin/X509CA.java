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
 
package se.anatom.ejbca.ca.caadmin;

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

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEREncodableVector;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
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
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.x509.X509V2CRLGenerator;
import org.bouncycastle.x509.X509V3CertificateGenerator;

import se.anatom.ejbca.SecConst;
import se.anatom.ejbca.ca.caadmin.extendedcaservices.ExtendedCAServiceNotActiveException;
import se.anatom.ejbca.ca.caadmin.extendedcaservices.ExtendedCAServiceRequest;
import se.anatom.ejbca.ca.caadmin.extendedcaservices.ExtendedCAServiceRequestException;
import se.anatom.ejbca.ca.caadmin.extendedcaservices.ExtendedCAServiceResponse;
import se.anatom.ejbca.ca.caadmin.extendedcaservices.IllegalExtendedCAServiceRequestException;
import se.anatom.ejbca.ca.caadmin.extendedcaservices.OCSPCAServiceRequest;
import se.anatom.ejbca.ca.caadmin.extendedcaservices.OCSPCAServiceResponse;
import se.anatom.ejbca.ca.crl.RevokedCertInfo;
import se.anatom.ejbca.ca.exception.CATokenOfflineException;
import se.anatom.ejbca.ca.exception.IllegalKeyStoreException;
import se.anatom.ejbca.ca.exception.SignRequestSignatureException;
import se.anatom.ejbca.ca.sign.SernoGenerator;
import se.anatom.ejbca.ca.store.certificateprofiles.CertificateProfile;
import se.anatom.ejbca.common.UserDataVO;
import se.anatom.ejbca.util.CertTools;
import se.anatom.ejbca.util.StringTools;

/**
 * X509CA is a implementation of a CA and holds data specific for Certificate and CRL generation 
 * according to the X509 standard. 
 *
 * @version $Id: X509CA.java,v 1.43 2005-09-25 14:17:52 anatom Exp $
 */
public class X509CA extends CA implements Serializable {

    private static Logger log = Logger.getLogger(X509CA.class);

    // Default Values
    public static final float LATEST_VERSION = 1;

    private X509Name subjectx509name = null;
    
    private byte[]  keyId = new byte[] { 1, 2, 3, 4, 5 };
    
    
    // protected fields.
    protected static final String POLICYID                       = "policyid";
    protected static final String SUBJECTALTNAME                 = "subjectaltname";
    protected static final String USEAUTHORITYKEYIDENTIFIER      = "useauthoritykeyidentifier";
    protected static final String AUTHORITYKEYIDENTIFIERCRITICAL = "authoritykeyidentifiercritical";
    protected static final String USECRLNUMBER                   = "usecrlnumber";
    protected static final String CRLNUMBERCRITICAL              = "crlnumbercritical";

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
      data.put(USEAUTHORITYKEYIDENTIFIER, new Boolean(useauthoritykeyidentifier));
    }
    
    public boolean  getAuthorityKeyIdentifierCritical(){
      return ((Boolean)data.get(AUTHORITYKEYIDENTIFIERCRITICAL)).booleanValue();
    }
    public void setAuthorityKeyIdentifierCritical(boolean authoritykeyidentifiercritical) {
      data.put(AUTHORITYKEYIDENTIFIERCRITICAL, new Boolean(authoritykeyidentifiercritical));
    }

    public boolean  getUseCRLNumber(){return ((Boolean)data.get(USECRLNUMBER)).booleanValue();}
    public void setUseCRLNumber(boolean usecrlnumber) {data.put(USECRLNUMBER, new Boolean(usecrlnumber));}
    
    public boolean  getCRLNumberCritical(){return ((Boolean)data.get(CRLNUMBERCRITICAL)).booleanValue();}
    public void setCRLNumberCritical(boolean crlnumbercritical) {data.put(CRLNUMBERCRITICAL, new Boolean(crlnumbercritical));}
    
    
    public void updateCA(CAInfo cainfo) throws Exception{
      super.updateCA(cainfo); 
      X509CAInfo info = (X509CAInfo) cainfo;

      setUseAuthorityKeyIdentifier(info.getUseAuthorityKeyIdentifier());
      setAuthorityKeyIdentifierCritical(info.getAuthorityKeyIdentifierCritical()); 
      setUseCRLNumber(info.getUseCRLNumber());
      setCRLNumberCritical(info.getCRLNumberCritical());
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
                    getUseCRLNumber(), getCRLNumberCritical(), getFinishUser(), externalcaserviceinfos); 
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
        X509V3CertificateGenerator certgen = new X509V3CertificateGenerator();
        // Serialnumber is random bits, where random generator is initialized by the
        // serno generator.
        BigInteger serno = SernoGenerator.instance().getSerno();
        certgen.setSerialNumber(serno);
        certgen.setNotBefore(firstDate);
        certgen.setNotAfter(lastDate);
        certgen.setSignatureAlgorithm(sigAlg);
        // Make DNs
        String dn = subject.getDN(); 
        if(certProfile.getUseCNPostfix()){
          dn = CertTools.insertCNPostfix(dn,certProfile.getCNPostfix());	
        }
        
        String altName = subject.getSubjectAltName(); 
      
        certgen.setSubjectDN(CertTools.stringToBcX509Name(dn));
        X509Name caname = getSubjectDNAsX509Name();
        certgen.setIssuerDN(caname);
        certgen.setPublicKey(publicKey);

        // Basic constranits, all subcerts are NOT CAs
        if (certProfile.getUseBasicConstraints() == true) {
            boolean isCA = false;
            if ((certProfile.getType() == CertificateProfile.TYPE_SUBCA)
                || (certProfile.getType() == CertificateProfile.TYPE_ROOTCA))
                isCA = true;
            BasicConstraints bc = new BasicConstraints(isCA);
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
            String email = CertTools.getEmailFromDN(altName);
            DEREncodableVector vec = new DEREncodableVector();
            if (email != null) {
                GeneralName gn = new GeneralName(1, new DERIA5String(email));
                vec.add(gn);
            }
            
            ArrayList dns = CertTools.getPartsFromDN(altName, CertTools.DNS);
            if (!dns.isEmpty()) {            
				Iterator iter = dns.iterator();
				while (iter.hasNext()) {
					GeneralName gn = new GeneralName(2, new DERIA5String((String)iter.next()));
					vec.add(gn);
				}
            }
            			            
            ArrayList uri = CertTools.getPartsFromDN(altName, CertTools.URI);
			if (!uri.isEmpty()) {            
				Iterator iter = uri.iterator();
				while (iter.hasNext()) {
					GeneralName gn = new GeneralName(6, new DERIA5String((String)iter.next()));
					vec.add(gn);
				}
			}

			uri = CertTools.getPartsFromDN(altName, CertTools.URI1);
			if (!uri.isEmpty()) {            
				Iterator iter = uri.iterator();
				while (iter.hasNext()) {
					GeneralName gn = new GeneralName(6, new DERIA5String((String)iter.next()));
					vec.add(gn);
				}
			}
            
                    
            ArrayList ipstr = CertTools.getPartsFromDN(altName, CertTools.IPADDR);
			if (!ipstr.isEmpty()) {            
				Iterator iter = ipstr.iterator();
				while (iter.hasNext()) {
					byte[] ipoctets = StringTools.ipStringToOctets((String)iter.next());
					GeneralName gn = new GeneralName(7, new DEROctetString(ipoctets));
					vec.add(gn);
				}
			}
			            
            ArrayList upn =  CertTools.getPartsFromDN(altName, CertTools.UPN);
			if (!upn.isEmpty()) {            
				Iterator iter = upn.iterator();				
				while (iter.hasNext()) {
					ASN1EncodableVector v = new ASN1EncodableVector();
					v.add(new DERObjectIdentifier(CertTools.UPN_OBJECTID));
					v.add(new DERTaggedObject(true, 0, new DERUTF8String((String)iter.next())));
					//GeneralName gn = new GeneralName(new DERSequence(v), 0);
					DERObject gn = new DERTaggedObject(false, 0, new DERSequence(v));
					vec.add(gn);
				}
			}
            
          
            ArrayList guid =  CertTools.getPartsFromDN(altName, CertTools.GUID);
			if (!guid.isEmpty()) {            
				Iterator iter = guid.iterator();				
				while (iter.hasNext()) {					
	                ASN1EncodableVector v = new ASN1EncodableVector();
	                byte[] guidbytes = Hex.decode((String)iter.next());
	                if (guidbytes != null) {
	                    v.add(new DERObjectIdentifier(CertTools.GUID_OBJECTID));
	                    v.add(new DERTaggedObject(true, 0, new DEROctetString(guidbytes)));
	                    DERObject gn = new DERTaggedObject(false, 0, new DERSequence(v));
	                    vec.add(gn);                    
	                } else {
	                    log.error("Cannot decode hexadecimal guid: "+guid);
	                }
				}
            }            
            if (vec.size() > 0) {
                GeneralNames san = new GeneralNames(new DERSequence(vec));
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
             // Multiple CDPs are spearated with the ';' sign
            StringTokenizer tokenizer = new StringTokenizer(certProfile.getCRLDistributionPointURI(), ";", false);
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
        X509V2CRLGenerator crlgen = new X509V2CRLGenerator();
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
    
    
   // private help methods
    private X509Name getSubjectDNAsX509Name(){
      if(subjectx509name == null){
        subjectx509name = CertTools.stringToBcX509Name(getSubjectDN());  
      }
        
      return subjectx509name;  
    }

}

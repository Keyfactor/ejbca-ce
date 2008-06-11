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
 
package org.ejbca.ui.web.admin.rainterface;


import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.HashMap;

import org.bouncycastle.util.encoders.Hex;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfile;
import org.ejbca.cvc.CVCertificateBody;
import org.ejbca.cvc.CardVerifiableCertificate;
import org.ejbca.ui.web.admin.configuration.EjbcaWebBean;
import org.ejbca.util.CertTools;
import org.ejbca.util.cert.QCStatementExtension;
import org.ejbca.util.cert.SubjectDirAttrExtension;
import org.ejbca.util.dn.DNFieldExtractor;



/**
 * A class transforming X509 certificate data inte more readable form used
 * by JSP pages.
 *
 * @author  Philip Vendil
 * @version $Id$
 */
public class CertificateView implements java.io.Serializable {

   public static final int DIGITALSIGNATURE = CertificateProfile.DIGITALSIGNATURE;
   public static final int NONREPUDIATION   = CertificateProfile.NONREPUDIATION;
   public static final int KEYENCIPHERMENT  = CertificateProfile.KEYENCIPHERMENT;
   public static final int DATAENCIPHERMENT = CertificateProfile.DATAENCIPHERMENT;
   public static final int KEYAGREEMENT     = CertificateProfile.KEYAGREEMENT;
   public static final int KEYCERTSIGN      = CertificateProfile.KEYCERTSIGN;
   public static final int CRLSIGN          = CertificateProfile.CRLSIGN;
   public static final int ENCIPHERONLY     = CertificateProfile.ENCIPHERONLY;
   public static final int DECIPHERONLY     = CertificateProfile.DECIPHERONLY;
   
   public static final String[] KEYUSAGETEXTS = {"DIGITALSIGNATURE","NONREPUDIATION", "KEYENCIPHERMENT", "DATAENCIPHERMENT", "KEYAGREEMENT", "KEYCERTSIGN", "CRLSIGN", "ENCIPHERONLY", "DECIPHERONLY" };
   
   /** Array for texts that must match the indexes in CertificateProfile.EXTENDEDKEYUSAGEOIDSTRINGS.
    * if an extended key usage should not be displayed in the GUI, put null as value. 
    * This is done for deprecated ipsec key usages below. "IPSECENDSYSTEM", "IPSECTUNNEL", "IPSECUSER"  
    */
   public static final String[] EXTENDEDKEYUSAGETEXTS = {"ANYEXTENDEDKEYUSAGE","SERVERAUTH", "CLIENTAUTH", 
                                    "CODESIGNING", "EMAILPROTECTION", null, 
                                    null, null, "TIMESTAMPING", "SMARTCARDLOGON",
                                    "OCSPSIGNER", "EFS_CRYPTO", "EFS_RECOVERY", "IPSECIKE",
                                    "SCVPSERVER", "SCVPCLIENT"};


    /** Creates a new instance of CertificateView */
    public CertificateView(Certificate certificate, RevokedInfoView revokedinfo, String username) {
      this.certificate=certificate;
      this.revokedinfo= revokedinfo;
      this.username=username;

      subjectdnfieldextractor = new DNFieldExtractor(CertTools.getSubjectDN(certificate), DNFieldExtractor.TYPE_SUBJECTDN);
      issuerdnfieldextractor  = new DNFieldExtractor(CertTools.getIssuerDN(certificate), DNFieldExtractor.TYPE_SUBJECTDN);

      // Build HashMap of Extended KeyUsage OIDs (String) to Text representation (String)
      if(extendedkeyusageoidtotextmap == null){
        extendedkeyusageoidtotextmap = new HashMap();
        for(int i=0; i < EXTENDEDKEYUSAGETEXTS.length; i++){
           extendedkeyusageoidtotextmap.put(CertificateProfile.EXTENDEDKEYUSAGEOIDSTRINGS[i], EXTENDEDKEYUSAGETEXTS[i]);   
        }
      }
      
    }


    // Public methods
    /** Method that returns the version number of the X509 certificate. */
    public String getVersion() {
        if (certificate instanceof X509Certificate) {
        	X509Certificate x509cert = (X509Certificate)certificate;
            return Integer.toString(x509cert.getVersion());
        } else {
        	return Integer.valueOf(CVCertificateBody.CVC_VERSION).toString();
        }
    }

    public String getType() {
      return certificate.getType();
    }

    public String getSerialNumber() {
      return CertTools.getSerialNumber(certificate).toString(16).toUpperCase();
    }

    public BigInteger getSerialNumberBigInt() {
      return CertTools.getSerialNumber(certificate);
    }

    public String getIssuerDN() {
      return CertTools.getIssuerDN(certificate);
    }

    public String getIssuerDNField(int field, int number) {
      return issuerdnfieldextractor.getField(field, number);
    }

    public String getSubjectDN() {
      return CertTools.getSubjectDN(certificate);
    }

    public String getSubjectDNField(int field, int number) {
      return subjectdnfieldextractor.getField(field, number);
    }

    public Date getValidFrom() {
      return CertTools.getNotBefore(certificate);
    }

    public Date getValidTo() {
      return CertTools.getNotAfter(certificate);
    }

    public boolean checkValidity(){
      boolean valid = true;
      try{
        CertTools.checkValidity(certificate, new Date());
      }
      catch( CertificateExpiredException e){
        valid=false;
      }
      catch(CertificateNotYetValidException e){
         valid=false;
      }

      return valid;
    }

    public boolean checkValidity(Date date)  {
      boolean valid = true;
      try{
        CertTools.checkValidity(certificate, date);
      }
      catch( CertificateExpiredException e){
        valid=false;
      }
      catch(CertificateNotYetValidException e){
         valid=false;
      }

      return valid;
    }

    public String getPublicKeyAlgorithm(){
      return certificate.getPublicKey().getAlgorithm();
    }

    public String getPublicKeyLength(){
      String keylength = null;
      if( certificate.getPublicKey() instanceof RSAPublicKey){
        keylength = "" + ((RSAPublicKey)certificate.getPublicKey()).getModulus().bitLength();
      }
      return keylength;
    }

    public String getSignatureAlgoritm() {
      return CertTools.getSignatureAlgorithm(certificate);
    }

    /** Method that returns if key is allowed for given usage. Usage must be one of this class key usage constants. */
    public boolean getKeyUsage(int usage) {
    	boolean returnval = false;
    	if (certificate instanceof X509Certificate) {
    		X509Certificate x509cert = (X509Certificate)certificate;
    		if(x509cert.getKeyUsage() != null)
    			returnval= x509cert.getKeyUsage()[usage];
    	} else {
    		returnval = false;
    	}
    	return returnval;
    }

    public String[] getExtendedKeyUsageAsTexts(){
      java.util.List extendedkeyusage = null;  
      if (certificate instanceof X509Certificate) {
    	  X509Certificate x509cert = (X509Certificate)certificate;
          try {  
              extendedkeyusage = x509cert.getExtendedKeyUsage();  
            } catch (java.security.cert.CertificateParsingException e) {}  
      }
      if(extendedkeyusage == null)    
        extendedkeyusage = new java.util.ArrayList();
      
      String[] returnval = new String[extendedkeyusage.size()];  
      for(int i=0; i < extendedkeyusage.size(); i++){
        returnval[i] = (String) extendedkeyusageoidtotextmap.get(extendedkeyusage.get(i));    
      }
        
      return returnval; 
    }

    public String getBasicConstraints(EjbcaWebBean ejbcawebbean) {
    	String retval = ejbcawebbean.getText("NONE");
    	if (certificate instanceof X509Certificate) {
    		X509Certificate x509cert = (X509Certificate)certificate;
    		int bc = x509cert.getBasicConstraints();
    		if (bc == Integer.MAX_VALUE) {
    			retval = ejbcawebbean.getText("CANOLIMIT");
    		} else if (bc == -1) {
    			retval = ejbcawebbean.getText("ENDENTITY");
    		} else {
    			retval = ejbcawebbean.getText("CAPATHLENGTH") + " : " + x509cert.getBasicConstraints();                    	     			
    		}
    	} else if (certificate.getType().equals("CVC")) {
    		CardVerifiableCertificate cvccert = (CardVerifiableCertificate)certificate;
    		try {
    			retval = cvccert.getCVCertificate().getCertificateBody().getAuthorizationTemplate().getAuthorizationField().getRole().name();
    		} catch (NoSuchFieldException e) {
    	    	retval = ejbcawebbean.getText("NONE");
    		}
    	}
    	return retval;
    }

    public String getSignature() {
      return (new java.math.BigInteger(CertTools.getSignature(certificate))).toString(16);
    }

    public String getSHA1Fingerprint(){
      String returnval = "";
      try {
         byte[] res = CertTools.generateSHA1Fingerprint(certificate.getEncoded());
         String ret = new String(Hex.encode(res));
         returnval = ret.toUpperCase();
      } catch (CertificateEncodingException cee) {
      }
      return  returnval;
    }

    public String getMD5Fingerprint(){
      String returnval = "";
      try {
         byte[] res = CertTools.generateMD5Fingerprint(certificate.getEncoded());
         String ret = new String(Hex.encode(res));
         returnval = ret.toUpperCase();
      } catch (CertificateEncodingException cee) {
      }
      return  returnval;
    }
     
     

    public boolean isRevoked(){
      return revokedinfo != null  && revokedinfo.isRevoked();     
    }

    public String[] getRevokationReasons(){
      String[] returnval = null;
      if(revokedinfo != null)
        returnval = revokedinfo.getRevokationReasons();
      return returnval;
    }

    public Date getRevokationDate(){
      Date returnval = null;
      if(revokedinfo != null)
        returnval = revokedinfo.getRevocationDate();
      return returnval;
    }

    public String getUsername(){
      return this.username;
    }

    public Certificate getCertificate(){
      return certificate;
    }
    
    public String getSubjectDirAttr() {
    	if(subjectdirattrstring == null) {
    		try {
    			subjectdirattrstring = SubjectDirAttrExtension.getSubjectDirectoryAttributes(certificate);
    		} catch (Exception e) {
    			subjectdirattrstring = e.getMessage();		
    		}
    	}
    	return subjectdirattrstring;
    }
    
    public String getSubjectAltName() {
    	if(subjectaltnamestring == null){  
    		try {
    			subjectaltnamestring = CertTools.getSubjectAlternativeName(certificate);
    		} catch (CertificateParsingException e) {
    			subjectaltnamestring = e.getMessage();		
    		} catch (IOException e) {
    			subjectaltnamestring = e.getMessage();		
			}                  
    	}        

      return subjectaltnamestring; 	
    }

    public boolean hasQcStatement() {
    	boolean ret = false; 
    	try {
			ret = QCStatementExtension.hasQcStatement(certificate);
		} catch (IOException e) {
			ret = false;
		}
		return ret;
    }
    // Private fields
    private Certificate  certificate;
    private DNFieldExtractor subjectdnfieldextractor, issuerdnfieldextractor;
    private RevokedInfoView  revokedinfo;
    private String           username;
    private String           subjectaltnamestring;
    private String           subjectdirattrstring;
    private static HashMap   extendedkeyusageoidtotextmap;
}

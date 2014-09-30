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
 
package org.ejbca.ui.web;


import java.io.IOException;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang.StringUtils;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificatetransparency.CertificateTransparency;
import org.cesecore.certificates.certificatetransparency.CertificateTransparencyFactory;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.certificates.util.DNFieldExtractor;
import org.cesecore.certificates.util.cert.QCStatementExtension;
import org.cesecore.certificates.util.cert.SubjectDirAttrExtension;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CertTools;
import org.ejbca.cvc.CVCertificateBody;
import org.ejbca.cvc.CardVerifiableCertificate;
import org.ejbca.util.HTMLTools;



/**
 * A class transforming X509 certificate data into more readable form used
 * by JSP pages.
 *
 * @version $Id$
 */
public class CertificateView implements Serializable {

    private static final long serialVersionUID = -3511834437471085177L;
    // Private fields
    private Certificate  certificate;
    private DNFieldExtractor subjectdnfieldextractor, issuerdnfieldextractor;
    private RevokedInfoView  revokedinfo;
    private String           username;
    private String           subjectaltnamestring;
    private String           subjectdirattrstring;

   public static final String[] KEYUSAGETEXTS = {"KU_DIGITALSIGNATURE","KU_NONREPUDIATION", "KU_KEYENCIPHERMENT", "KU_DATAENCIPHERMENT", "KU_KEYAGREEMENT", "KU_KEYCERTSIGN", "KU_CRLSIGN", "KU_ENCIPHERONLY", "KU_DECIPHERONLY" };
   

	/** Creates a new instance of CertificateView */
    public CertificateView(Certificate certificate, RevokedInfoView revokedinfo, String username) {
      this.certificate=certificate;
      this.revokedinfo= revokedinfo;
      this.username=username;

      subjectdnfieldextractor = new DNFieldExtractor(CertTools.getSubjectDN(certificate), DNFieldExtractor.TYPE_SUBJECTDN);
      issuerdnfieldextractor  = new DNFieldExtractor(CertTools.getIssuerDN(certificate), DNFieldExtractor.TYPE_SUBJECTDN);
      
    }


    // Public methods
    /** Method that returns the version number of the X509 certificate. */
    public String getVersion() {
        if (certificate instanceof X509Certificate) {
        	X509Certificate x509cert = (X509Certificate)certificate;
            return Integer.toString(x509cert.getVersion());
        } else {
        	return String.valueOf(CVCertificateBody.CVC_VERSION);
        }
    }

    public String getType() {
      return certificate.getType();
    }

    public String getSerialNumber() {
      return CertTools.getSerialNumberAsString(certificate);
    }

    public BigInteger getSerialNumberBigInt() {
      return CertTools.getSerialNumber(certificate);
    }

    public String getIssuerDN() {
    	return HTMLTools.htmlescape(CertTools.getIssuerDN(certificate));
    }

    public String getIssuerDNUnEscaped() {
        return CertTools.getIssuerDN(certificate);
      }

    public String getIssuerDNField(int field, int number) {
      return HTMLTools.htmlescape(issuerdnfieldextractor.getField(field, number));
    }

    public String getSubjectDN() {
    	return HTMLTools.htmlescape(CertTools.getSubjectDN(certificate));
    }

    public String getSubjectDNField(int field, int number) {
      return HTMLTools.htmlescape(subjectdnfieldextractor.getField(field, number));
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
    
    public String getKeySpec(String localizedBitsText) {
    	if( certificate.getPublicKey() instanceof ECPublicKey ) {
    		return AlgorithmTools.getKeySpecification(certificate.getPublicKey());
    	} else {
    		return "" + KeyTools.getKeyLength(certificate.getPublicKey()) + " " + localizedBitsText;
    	}
    }

    public String getPublicKeyLength(){
      int len = KeyTools.getKeyLength(certificate.getPublicKey());
      return len > 0 ? ""+len : null; 
    }

    public String getPublicKeyModulus(){
    	String mod = null;
    	if( certificate.getPublicKey() instanceof RSAPublicKey){
    		mod = "" + ((RSAPublicKey)certificate.getPublicKey()).getModulus().toString(16);
    		mod = mod.toUpperCase();
    		mod = StringUtils.abbreviate(mod, 50);
    	} else if( certificate.getPublicKey() instanceof DSAPublicKey){
    		mod = "" + ((DSAPublicKey)certificate.getPublicKey()).getY().toString(16);
    		mod = mod.toUpperCase();
    		mod = StringUtils.abbreviate(mod, 50);
    	} else if( certificate.getPublicKey() instanceof ECPublicKey){
    		mod = "" + ((ECPublicKey)certificate.getPublicKey()).getW().getAffineX().toString(16);
    		mod = mod + ((ECPublicKey)certificate.getPublicKey()).getW().getAffineY().toString(16);
    		mod = mod.toUpperCase();
    		mod = StringUtils.abbreviate(mod, 50);
    	}
    	return mod;
    }

    public String getSignatureAlgoritm() {
    	// Only used for displaying to user so we can use this value that always works
    	return AlgorithmTools.getCertSignatureAlgorithmNameAsString(certificate);
    }

    /** Method that returns if key is allowed for given usage. Usage must be one of this class key usage constants. */
    public boolean getKeyUsage(int usage) {
    	boolean returnval = false;
    	if (certificate instanceof X509Certificate) {
    		X509Certificate x509cert = (X509Certificate)certificate;
    		if(x509cert.getKeyUsage() != null) {
    			returnval= x509cert.getKeyUsage()[usage];
    		}
    	} else {
    		returnval = false;
    	}
    	return returnval;
    }

    public String[] getExtendedKeyUsageAsTexts(){
     List<String> extendedkeyusage = null;  
      if (certificate instanceof X509Certificate) {
    	  X509Certificate x509cert = (X509Certificate)certificate;
          try {  
              extendedkeyusage = x509cert.getExtendedKeyUsage();  
            } catch (java.security.cert.CertificateParsingException e) {}  
      }
      if(extendedkeyusage == null) {
        extendedkeyusage = new ArrayList<String>();
      }
      String[] returnval = new String[extendedkeyusage.size()]; 
      Map<String,String> map = CertificateProfile.getAllExtendedKeyUsageTexts();
      for(int i=0; i < extendedkeyusage.size(); i++){
        returnval[i] = (String)map.get(extendedkeyusage.get(i));    
      }
        
      return returnval; 
    }

    public String getBasicConstraints(String localizedNoneText, String localizedNolimitText, String localizedEndEntityText, String localizedCaPathLengthText) {
    	String retval = localizedNoneText;	//ejbcawebbean.getText("EXT_NONE");
    	if (certificate instanceof X509Certificate) {
    		X509Certificate x509cert = (X509Certificate)certificate;
    		int bc = x509cert.getBasicConstraints();
    		if (bc == Integer.MAX_VALUE) {
    			retval = localizedNolimitText;	//ejbcawebbean.getText("EXT_PKIX_BC_CANOLIMIT");
    		} else if (bc == -1) {
    			retval = localizedEndEntityText;	//ejbcawebbean.getText("EXT_PKIX_BC_ENDENTITY");
    		} else {
    			retval = localizedCaPathLengthText /*ejbcawebbean.getText("EXT_PKIX_BC_CAPATHLENGTH")*/ + " : " + x509cert.getBasicConstraints();                    	     			
    		}
    	} else if (certificate.getType().equals("CVC")) {
    		CardVerifiableCertificate cvccert = (CardVerifiableCertificate)certificate;
    		try {
    			retval = cvccert.getCVCertificate().getCertificateBody().getAuthorizationTemplate().getAuthorizationField().getAuthRole().toString();
    		} catch (NoSuchFieldException e) {
    	    	retval = localizedNoneText;	//ejbcawebbean.getText("EXT_NONE");
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

    public String getSHA256Fingerprint(){
        String returnval = "";
        try {
           byte[] res = CertTools.generateSHA256Fingerprint(certificate.getEncoded());
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

    public boolean isRevokedAndOnHold(){
    	return revokedinfo != null && revokedinfo.isRevokedAndOnHold();     
    }

    public boolean isRevoked(){
      return revokedinfo != null && revokedinfo.isRevoked();     
    }

    public String getRevocationReason(){
      String returnval = null;
      if(revokedinfo != null) {
        returnval = revokedinfo.getRevocationReason();
      }
      return returnval;
    }

    public Date getRevocationDate(){
      Date returnval = null;
      if(revokedinfo != null) {
        returnval = revokedinfo.getRevocationDate();
      }
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
    		subjectaltnamestring = CertTools.getSubjectAlternativeName(certificate);
    	}        

      return subjectaltnamestring; 	
    }
    
    public boolean hasNameConstraints() {
        if (certificate instanceof X509Certificate) {
            X509Certificate x509cert = (X509Certificate)certificate;
            byte[] ext = x509cert.getExtensionValue(Extension.nameConstraints.getId());
            return ext != null;
        }
        return false;
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

    public boolean hasCertificateTransparencySCTs() {
        CertificateTransparency ct = CertificateTransparencyFactory.getInstance();
        return (ct != null && ct.hasSCTs(certificate));
    }
}

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
import java.security.cert.CertificateParsingException;
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
import org.cesecore.certificates.certificate.CertificateData;
import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.cesecore.certificates.certificate.CertificateStatusHelper;
import org.cesecore.certificates.certificatetransparency.CertificateTransparency;
import org.cesecore.certificates.certificatetransparency.CertificateTransparencyFactory;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.certificates.util.DNFieldExtractor;
import org.cesecore.certificates.util.cert.QCStatementExtension;
import org.cesecore.certificates.util.cert.SubjectDirAttrExtension;
import org.cesecore.config.AvailableExtendedKeyUsagesConfiguration;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CertTools;
import org.cesecore.util.ValidityDate;
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
    private Certificate certificate;
    private DNFieldExtractor subjectDnFieldExtractor;
    private DNFieldExtractor issuerDnFieldExtractor;
    private RevokedInfoView revokedinfo;
    private String username;
    private String subjectaltnamestring;
    private String subjectdirattrstring;
    private CertificateData certificateData;

    public static final String[] KEYUSAGETEXTS = {"KU_DIGITALSIGNATURE","KU_NONREPUDIATION", "KU_KEYENCIPHERMENT", "KU_DATAENCIPHERMENT", "KU_KEYAGREEMENT", "KU_KEYCERTSIGN", "KU_CRLSIGN", "KU_ENCIPHERONLY", "KU_DECIPHERONLY" };
    public static final String UNKNOWN = "-";

    /** Creates a new instance of CertificateView */
    public CertificateView(final CertificateDataWrapper cdw) {
        certificateData = cdw.getCertificateData();
        revokedinfo = new RevokedInfoView(CertificateStatusHelper.getCertificateStatus(certificateData), getSerialNumberBigInt(certificate, certificateData));
        certificate = cdw.getCertificate();
        username = certificateData.getUsername();
        subjectDnFieldExtractor = new DNFieldExtractor(certificateData.getSubjectDN(), DNFieldExtractor.TYPE_SUBJECTDN);
        issuerDnFieldExtractor = new DNFieldExtractor(certificateData.getIssuerDN(), DNFieldExtractor.TYPE_SUBJECTDN);
    }

    /** Creates a new instance of CertificateView for CA certificates */
    public CertificateView(Certificate certificate, RevokedInfoView revokedinfo) {
        this.certificate=certificate;
        this.revokedinfo= revokedinfo;
        this.username=null;
        subjectDnFieldExtractor = new DNFieldExtractor(CertTools.getSubjectDN(certificate), DNFieldExtractor.TYPE_SUBJECTDN);
        subjectDnFieldExtractor = new DNFieldExtractor(CertTools.getIssuerDN(certificate), DNFieldExtractor.TYPE_SUBJECTDN);
    }

    /** Method that returns the version number of the X509 certificate. */
    public String getVersion() {
        if (certificate==null) {
            return UNKNOWN;
        }
        if (certificate instanceof X509Certificate) {
            X509Certificate x509cert = (X509Certificate)certificate;
            return Integer.toString(x509cert.getVersion());
        } else {
            return String.valueOf(CVCertificateBody.CVC_VERSION);
        }
    }

    public String getType() {
        if (certificate==null) {
            return UNKNOWN;
        }
        return certificate.getType();
    }

    public String getSerialNumber() {
        if (certificate==null) {
            return certificateData.getSerialNumberHex();
        }
        return CertTools.getSerialNumberAsString(certificate);
    }

    public BigInteger getSerialNumberBigInt() {
        return getSerialNumberBigInt(certificate, certificateData);
    }

    private BigInteger getSerialNumberBigInt(final Certificate certificate, final CertificateData certificateData) {
        if (certificate==null) {
            try {
                // This will work for X.509
                return new BigInteger(certificateData.getSerialNumber(), 10);
            } catch (NumberFormatException e) {
                return BigInteger.valueOf(0);
            }
        }
        return CertTools.getSerialNumber(certificate);
    }

    public String getIssuerDN() {
        if (certificate==null) {
            return HTMLTools.htmlescape(certificateData.getIssuerDN());
        }
    	return HTMLTools.htmlescape(CertTools.getIssuerDN(certificate));
    }

    public String getIssuerDNUnEscaped() {
        if (certificate==null) {
            return certificateData.getIssuerDN();
        }
        return CertTools.getIssuerDN(certificate);
      }

    public String getIssuerDNField(int field, int number) {
      return HTMLTools.htmlescape(issuerDnFieldExtractor.getField(field, number));
    }

    public String getSubjectDN() {
        if (certificate==null) {
            return HTMLTools.htmlescape(certificateData.getSubjectDN());
        }
    	return HTMLTools.htmlescape(CertTools.getSubjectDN(certificate));
    }

    public String getSubjectDNField(int field, int number) {
      return HTMLTools.htmlescape(subjectDnFieldExtractor.getField(field, number));
    }

    public Date getValidFrom() {
        if (certificate==null) {
            return new Date(0);
        }
        return CertTools.getNotBefore(certificate);
    }

    public String getValidFromString() {
        if (certificate==null) {
            return "-";
        }
        return ValidityDate.formatAsISO8601(CertTools.getNotBefore(certificate), ValidityDate.TIMEZONE_SERVER);
    }

    public Date getValidTo() {
        if (certificate==null) {
            return new Date(certificateData.getExpireDate());
        }
        return CertTools.getNotAfter(certificate);
    }

    public String getValidToString() {
        return ValidityDate.formatAsISO8601(getValidTo(), ValidityDate.TIMEZONE_SERVER);
    }

    public boolean checkValidity() {
        if (certificate==null) {
            // We can't check not before field in this case, so make a best effort
            return certificateData.getExpireDate()>=System.currentTimeMillis();
        }
        boolean valid = true;
        try {
            CertTools.checkValidity(certificate, new Date());
        } catch (CertificateExpiredException e) {
            valid = false;
        } catch (CertificateNotYetValidException e) {
            valid = false;
        }
        return valid;
    }

    public boolean checkValidity(final Date date)  {
        if (certificate==null) {
            // We can't check not before field in this case, so make a best effort
            return certificateData.getExpireDate()>=date.getTime();
        }
        boolean valid = true;
        try {
            CertTools.checkValidity(certificate, date);
        } catch (CertificateExpiredException e) {
            valid = false;
        } catch (CertificateNotYetValidException e) {
            valid = false;
        }
        return valid;
    }

    public String getPublicKeyAlgorithm(){
        if (certificate==null) {
            return UNKNOWN;
        }
        return certificate.getPublicKey().getAlgorithm();
    }
    
    public String getKeySpec(String localizedBitsText) {
        if (certificate==null) {
            return UNKNOWN;
        }
    	if (certificate.getPublicKey() instanceof ECPublicKey) {
    		return AlgorithmTools.getKeySpecification(certificate.getPublicKey());
    	} else {
    		return "" + KeyTools.getKeyLength(certificate.getPublicKey()) + " " + localizedBitsText;
    	}
    }

    public String getPublicKeyLength(){
        if (certificate==null) {
            return UNKNOWN;
        }
        int len = KeyTools.getKeyLength(certificate.getPublicKey());
        return len > 0 ? ""+len : null; 
    }

    public String getPublicKeyModulus(){
        if (certificate==null) {
            return UNKNOWN;
        }
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
        if (certificate==null) {
            // We could lookup the issuer and show a probably algorithm that was used, but we will never know for sure
            return UNKNOWN;
        }
    	// Only used for displaying to user so we can use this value that always works
    	return AlgorithmTools.getCertSignatureAlgorithmNameAsString(certificate);
    }

    /** Method that returns if key is allowed for given usage. Usage must be one of this class key usage constants. */
    public boolean getKeyUsage(int usage) {
        if (certificate==null) {
            return false;
        }
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

    public String[] getExtendedKeyUsageAsTexts(AvailableExtendedKeyUsagesConfiguration ekuConfig){
        if (certificate==null) {
            return new String[0];
        }
        List<String> extendedkeyusage = null;
        if (certificate instanceof X509Certificate) {
            X509Certificate x509cert = (X509Certificate)certificate;
            try {
                extendedkeyusage = x509cert.getExtendedKeyUsage();  
            } catch (CertificateParsingException e) {}
        }
        if (extendedkeyusage == null) {
            extendedkeyusage = new ArrayList<String>();
        }
        final String[] returnval = new String[extendedkeyusage.size()];
        for (int i=0; i<extendedkeyusage.size(); i++) {
            returnval[i] = ekuConfig.getExtKeyUsageName(extendedkeyusage.get(i));
        }
        return returnval; 
    }

    public String getBasicConstraints(String localizedNoneText, String localizedNolimitText, String localizedEndEntityText, String localizedCaPathLengthText) {
        if (certificate==null) {
            return UNKNOWN;
        }
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
        if (certificate==null) {
            return UNKNOWN;
        }
        return new BigInteger(CertTools.getSignature(certificate)).toString(16);
    }

    public String getSHA1Fingerprint(){
        if (certificate==null) {
            return certificateData.getFingerprint().toUpperCase();
        }
        String returnval = "";
        try {
            byte[] res = CertTools.generateSHA1Fingerprint(certificate.getEncoded());
            String ret = new String(Hex.encode(res));
            returnval = ret.toUpperCase();
        } catch (CertificateEncodingException e) {
        }
        return returnval;
    }

    public String getSHA256Fingerprint(){
        if (certificate==null) {
            return UNKNOWN;
        }
        String returnval = "";
        try {
            byte[] res = CertTools.generateSHA256Fingerprint(certificate.getEncoded());
            String ret = new String(Hex.encode(res));
            returnval = ret.toUpperCase();
        } catch (CertificateEncodingException e) {
        }
        return returnval;
    }

    public String getMD5Fingerprint(){
        if (certificate==null) {
            return UNKNOWN;
        }
        String returnval = "";
        try {
            byte[] res = CertTools.generateMD5Fingerprint(certificate.getEncoded());
            String ret = new String(Hex.encode(res));
            returnval = ret.toUpperCase();
        } catch (CertificateEncodingException e) {
        }
        return returnval;
    }

    public boolean isRevokedAndOnHold(){
    	return revokedinfo != null && revokedinfo.isRevokedAndOnHold();     
    }

    public boolean isRevoked(){
        return revokedinfo != null && revokedinfo.isRevoked();     
    }

    public String getRevocationReason(){
        String returnval = null;
        if (revokedinfo != null) {
            returnval = revokedinfo.getRevocationReason();
        }
        return returnval;
    }

    public Date getRevocationDate(){
        Date returnval = null;
        if (revokedinfo != null) {
            returnval = revokedinfo.getRevocationDate();
        }
        return returnval;
    }

    public String getUsername(){
        return username;
    }

    public Certificate getCertificate(){
        return certificate;
    }
    
    public String getSubjectDirAttr() {
        if (certificate==null) {
            return UNKNOWN;
        }
        if (subjectdirattrstring == null) {
            try {
                subjectdirattrstring = SubjectDirAttrExtension.getSubjectDirectoryAttributes(certificate);
            } catch (Exception e) {
                subjectdirattrstring = e.getMessage();
            }
        }
        return subjectdirattrstring;
    }
    
    public String getSubjectAltName() {
        if (certificate==null) {
            return UNKNOWN;
        }
        if (subjectaltnamestring == null) {
            subjectaltnamestring = CertTools.getSubjectAlternativeName(certificate);
        }        
        return subjectaltnamestring; 	
    }
    
    public boolean hasNameConstraints() {
        if (certificate==null) {
            return false;
        }
        if (certificate instanceof X509Certificate) {
            X509Certificate x509cert = (X509Certificate)certificate;
            byte[] ext = x509cert.getExtensionValue(Extension.nameConstraints.getId());
            return ext != null;
        }
        return false;
    }

    public boolean hasQcStatement() {
        if (certificate==null) {
            return false;
        }
    	boolean ret = false; 
    	try {
			ret = QCStatementExtension.hasQcStatement(certificate);
		} catch (IOException e) {
			ret = false;
		}
		return ret;
    }

    public boolean hasCertificateTransparencySCTs() {
        if (certificate==null) {
            return false;
        }
        CertificateTransparency ct = CertificateTransparencyFactory.getInstance();
        return (ct != null && ct.hasSCTs(certificate));
    }
}

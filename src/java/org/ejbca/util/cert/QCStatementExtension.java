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

package org.ejbca.util.cert;

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.qualified.ETSIQCObjectIdentifiers;
import org.bouncycastle.asn1.x509.qualified.MonetaryValue;
import org.bouncycastle.asn1.x509.qualified.QCStatement;
import org.bouncycastle.asn1.x509.qualified.RFC3739QCObjectIdentifiers;
import org.bouncycastle.asn1.x509.qualified.SemanticsInformation;
import org.ejbca.util.CertTools;

/**
 * A class for reading values from QC-statement extension.
 *
 * @author  Tomas Gustavsson
 * @version $Id$
 */
public class QCStatementExtension extends CertTools {

    private static Logger log = Logger.getLogger(SubjectDirAttrExtension.class);

    /**
     * inhibits creation of new SubjectDirAttrExtension
     */
    private QCStatementExtension() {
    }
    
    /** Returns true if the certificate contains a QC-statements extension.
     * 
     * @param cert Certificate containing the extension
     * @return true or false.
     * @throws IOException if there is a problem parsing the certificate
     */
    public static boolean hasQcStatement(Certificate cert) throws IOException {
    	boolean ret = false;
        if (cert instanceof X509Certificate) {
			X509Certificate x509cert = (X509Certificate) cert;
	        DERObject obj = getExtensionValue(x509cert, X509Extensions.QCStatements.getId());
	        if (obj != null) {
	            ret = true;
	        }
        }
        return ret;
    }
    /** Returns all the 'statementId' defined in the QCStatement extension (rfc3739).
     * 
     * @param cert Certificate containing the extension
     * @return Collection of String with the oid, for example "1.1.1.2", or empty Collection if no identifier is found, never returns null.
     * @throws IOException if there is a problem parsing the certificate
     */
    public static Collection getQcStatementIds(Certificate cert) throws IOException {
        ArrayList ret = new ArrayList();
        if (cert instanceof X509Certificate) {
			X509Certificate x509cert = (X509Certificate) cert;
            DERObject obj = getExtensionValue(x509cert, X509Extensions.QCStatements.getId());
            if (obj == null) {
                return ret;
            }
            ASN1Sequence seq = (ASN1Sequence)obj;
            for (int i = 0; i < seq.size(); i++) {
                QCStatement qc = QCStatement.getInstance(seq.getObjectAt(i));
                DERObjectIdentifier oid = qc.getStatementId();
                if (oid != null) {
                    ret.add(oid.getId());
                }        	
            }
        }
        return ret;
    }
    /** Returns the value limit ETSI QCStatement if present.
     * 
     * @param cert Certificate possibly containing the QCStatement extension
     * @return String with the value and currency (ex '50000 SEK')or null if the extension is not present
     * @throws IOException if there is a problem parsing the certificate
     */
    public static String getQcStatementValueLimit(Certificate cert) throws IOException {
    	String ret = null;
        if (cert instanceof X509Certificate) {
			X509Certificate x509cert = (X509Certificate) cert;
	        DERObject obj = getExtensionValue(x509cert, X509Extensions.QCStatements.getId());
	        if (obj == null) {
	            return null;
	        }
	        ASN1Sequence seq = (ASN1Sequence)obj;
	        MonetaryValue mv = null;
	        // Look through all the QCStatements and see if we have a stadard ETSI LimitValue
	        for (int i = 0; i < seq.size(); i++) {
	            QCStatement qc = QCStatement.getInstance(seq.getObjectAt(i));
	            DERObjectIdentifier oid = qc.getStatementId();
	            if (oid != null) {
	            	if (oid.equals(ETSIQCObjectIdentifiers.id_etsi_qcs_LimiteValue)) {
	                    // We MAY have a MonetaryValue object here
	                    ASN1Encodable enc = qc.getStatementInfo();
	                    if (enc != null) {
	                    	mv = MonetaryValue.getInstance(enc);
	                        // We can break the loop now, we got it!
	                        break;
	                    }
	            	}
	            }        	
	        }
	        if (mv != null) {
	        	BigInteger amount = mv.getAmount();
	        	BigInteger exp = mv.getExponent();
	        	BigInteger ten = BigInteger.valueOf(10);
	        	// A possibly gotcha here if the monetary value is larger than what fits in a long...
	        	long value = amount.longValue() * (ten.pow(exp.intValue())).longValue();
	        	if (value < 0) {
	        		log.error("ETSI LimitValue amount is < 0.");
	        	}
	        	String curr = mv.getCurrency().getAlphabetic();
	        	if (curr == null) {
	        		log.error("ETSI LimitValue currency is null");
	        	}
	        	if ( (value >= 0) && (curr != null) ) {
	        		ret = value + " "+curr;
	        	}
	        }
        }
    	return ret;    	
    }
    
    /** Returns the 'NameRegistrationAuthorities' defined in the QCStatement extension (rfc3739).
     * 
     * @param cert Certificate containing the extension
     * @return String with for example 'rfc822Name=foo2bar.se, rfc822Name=bar2foo.se' etc. Supports email, dns and uri name, or null of no RAs are found.
     * @throws IOException if there is a problem parsing the certificate
     */
    public static String getQcStatementAuthorities(Certificate cert) throws IOException {
        String ret = null;
        if (cert instanceof X509Certificate) {
			X509Certificate x509cert = (X509Certificate) cert;
	        DERObject obj = getExtensionValue(x509cert, X509Extensions.QCStatements.getId());
	        if (obj == null) {
	            return null;
	        }
	        ASN1Sequence seq = (ASN1Sequence)obj;
	        SemanticsInformation si = null;
	        // Look through all the QCStatements and see if we have a standard RFC3739 pkixQCSyntax
	        for (int i = 0; i < seq.size(); i++) {
	            QCStatement qc = QCStatement.getInstance(seq.getObjectAt(i));
	            DERObjectIdentifier oid = qc.getStatementId();
	            if (oid != null) {
	            	if (oid.equals(RFC3739QCObjectIdentifiers.id_qcs_pkixQCSyntax_v1) || oid.equals(RFC3739QCObjectIdentifiers.id_qcs_pkixQCSyntax_v2)) {
	                    // We MAY have a SemanticsInformation object here
	                    ASN1Encodable enc = qc.getStatementInfo();
	                    if (enc != null) {
	                        si = SemanticsInformation.getInstance(enc);
	                        // We can break the loop now, we got it!
	                        break;
	                    }
	            	}
	            }        	
	        }
	        if (si != null) {
	            GeneralName[] gns = si.getNameRegistrationAuthorities();
	            if (gns == null) {
	                return null;
	            }
	            StringBuffer strBuf = new StringBuffer(); 
	            for (int i = 0; i < gns.length; i++) {
	                GeneralName gn = gns[i];
	                if (strBuf.length() != 0) {
	                    // Append comma so we get nice formatting if there are more than one authority
	                    strBuf.append(", ");
	                }
	                String str = getGeneralNameString(gn.getTagNo(), gn.getName());
	                if (str != null) {
	                    strBuf.append(str);
	                }
	            }
	            if (strBuf.length() > 0) {
	                ret = strBuf.toString();
	            }
	        }
        }
        return ret;
    }

}

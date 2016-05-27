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
package org.cesecore.certificates.util.cert;

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.qualified.ETSIQCObjectIdentifiers;
import org.bouncycastle.asn1.x509.qualified.MonetaryValue;
import org.bouncycastle.asn1.x509.qualified.QCStatement;
import org.bouncycastle.asn1.x509.qualified.RFC3739QCObjectIdentifiers;
import org.bouncycastle.asn1.x509.qualified.SemanticsInformation;
import org.cesecore.util.CertTools;

/**
 * A class for reading values from QC-statement extension.
 *
 * @version $Id$
 */
public final class QCStatementExtension extends CertTools {

    private static final Logger log = Logger.getLogger(QCStatementExtension.class);

    /**
     * inhibits creation of new SubjectDirAttrExtension
     */
    private QCStatementExtension() {
    	super();
    }
    
    /** Returns true if the certificate contains a QC-statements extension.
     * 
     * @param cert Certificate containing the extension
     * @return true or false.
     */
    public static boolean hasQcStatement(final Certificate cert) {
    	boolean ret = false;
        if (cert instanceof X509Certificate) {
        	final X509Certificate x509cert = (X509Certificate) cert;
        	final ASN1Primitive obj = getExtensionValue(x509cert, Extension.qCStatements.getId());
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
    public static Collection<String> getQcStatementIds(final Certificate cert) throws IOException {
    	final ArrayList<String> ret = new ArrayList<String>();
        if (cert instanceof X509Certificate) {
        	final X509Certificate x509cert = (X509Certificate) cert;
        	final ASN1Primitive obj = getExtensionValue(x509cert, Extension.qCStatements.getId());
            if (obj == null) {
                return ret;
            }
            final ASN1Sequence seq = (ASN1Sequence)obj;
            for (int i = 0; i < seq.size(); i++) {
            	final QCStatement qc = QCStatement.getInstance(seq.getObjectAt(i));
            	final ASN1ObjectIdentifier oid = qc.getStatementId();
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
    public static String getQcStatementValueLimit(final Certificate cert) throws IOException {
    	String ret = null;
        if (cert instanceof X509Certificate) {
        	final X509Certificate x509cert = (X509Certificate) cert;
        	final ASN1Primitive obj = getExtensionValue(x509cert, Extension.qCStatements.getId());
	        if (obj == null) {
	            return null;
	        }
	        final ASN1Sequence seq = (ASN1Sequence)obj;
	        MonetaryValue mv = null;
	        // Look through all the QCStatements and see if we have a stadard ETSI LimitValue
	        for (int i = 0; i < seq.size(); i++) {
	        	final QCStatement qc = QCStatement.getInstance(seq.getObjectAt(i));
	        	final ASN1ObjectIdentifier oid = qc.getStatementId();
	        	if ((oid != null) && oid.equals(ETSIQCObjectIdentifiers.id_etsi_qcs_LimiteValue)) {
	        		// We MAY have a MonetaryValue object here
	        		final ASN1Encodable enc = qc.getStatementInfo();
	        		if (enc != null) {
	        			mv = MonetaryValue.getInstance(enc);
	        			// We can break the loop now, we got it!
	        			break;
	        		}
	        	}
	        }
	        if (mv != null) {
	        	final BigInteger amount = mv.getAmount();
	        	final BigInteger exp = mv.getExponent();
	        	final BigInteger ten = BigInteger.valueOf(10);
	        	// A possibly gotcha here if the monetary value is larger than what fits in a long...
	        	final long value = amount.longValue() * (ten.pow(exp.intValue())).longValue();
	        	if (value < 0) {
	        		log.error("ETSI LimitValue amount is < 0.");
	        	}
	        	final String curr = mv.getCurrency().getAlphabetic();
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
    public static String getQcStatementAuthorities(final Certificate cert) throws IOException {
        String ret = null;
        if (cert instanceof X509Certificate) {
        	final X509Certificate x509cert = (X509Certificate) cert;
        	final ASN1Primitive obj = getExtensionValue(x509cert, Extension.qCStatements.getId());
	        if (obj == null) {
	            return null;
	        }
	        final ASN1Sequence seq = (ASN1Sequence)obj;
	        SemanticsInformation si = null;
	        // Look through all the QCStatements and see if we have a standard RFC3739 pkixQCSyntax
	        for (int i = 0; i < seq.size(); i++) {
	        	final QCStatement qc = QCStatement.getInstance(seq.getObjectAt(i));
	        	final ASN1ObjectIdentifier oid = qc.getStatementId();
	        	if ((oid != null) && (oid.equals(RFC3739QCObjectIdentifiers.id_qcs_pkixQCSyntax_v1) || oid.equals(RFC3739QCObjectIdentifiers.id_qcs_pkixQCSyntax_v2))) {
	        		// We MAY have a SemanticsInformation object here
	        		final ASN1Encodable enc = qc.getStatementInfo();
	        		if (enc != null) {
	        			si = SemanticsInformation.getInstance(enc);
	        			// We can break the loop now, we got it!
	        			break;
	        		}
	        	}
	        }
	        if (si != null) {
	        	final GeneralName[] gns = si.getNameRegistrationAuthorities();
	            if (gns == null) {
	                return null;
	            }
	            final StringBuilder strBuf = new StringBuilder(); 
	            for (int i = 0; i < gns.length; i++) {
	            	final GeneralName gn = gns[i];
	                if (strBuf.length() != 0) {
	                    // Append comma so we get nice formatting if there are more than one authority
	                    strBuf.append(", ");
	                }
	                final String str = getGeneralNameString(gn.getTagNo(), gn.getName());
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

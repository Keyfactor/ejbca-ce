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
package org.cesecore.certificates.certificate.certextensions;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.util.ArrayList;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x509.qualified.ETSIQCObjectIdentifiers;
import org.bouncycastle.asn1.x509.qualified.QCStatement;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.certificates.certificate.certextensions.standard.QcStatement;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.util.cert.QCStatementExtension;
import org.junit.Test;

/**
 * @version $Id: BasicCertificateExtensionTest.java 21785 2015-09-02 21:39:25Z aveen4711 $
 */
public class QcStatementTest {
    private static Logger log = Logger.getLogger(QcStatementTest.class);
	
    @Test
    public void testQcStatement() throws CertificateExtensionException, IOException {
        CertificateProfile prof = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        prof.setUseQCStatement(true);
        prof.setUseQCEtsiQCCompliance(true);
        prof.setUseQCEtsiSignatureDevice(true);
        prof.setUseQCEtsiType(true);
        prof.setQCEtsiType("0.4.0.1862.1.6.1");
        prof.setUseQCEtsiPDS(true);
        prof.setQCEtsiPdsUrl("http://qcs.localhost/QcPDS");
        prof.setQCEtsiPdsLang("en");
        QcStatement statement = new QcStatement();
        byte[] value = statement.getValueEncoded(null, null, prof, null, null, null);
        @SuppressWarnings("resource")
        final String dump = ASN1Dump.dumpAsString(new ASN1InputStream(value).readObject(), true);
        log.info(dump);
        // Hex dump can be used in Custom Certificate Extensions
        log.info(new String(Hex.encode(value)));
        // Dump included IDs
        final ASN1Sequence seq = (ASN1Sequence) ASN1Sequence.fromByteArray(value);
        // This is just a loop to get all the statement IDs in the QcStatements extension, so we can view them and count them
        ArrayList<String> oids = new ArrayList<String>();
        for (int i = 0; i < seq.size(); i++) {
            final QCStatement qc = QCStatement.getInstance(seq.getObjectAt(i));
            final ASN1ObjectIdentifier oid = qc.getStatementId();
            if (oid != null) {
                oids.add(oid.getId());
            } else {
                fail("QC statements have empty statement");
            }
        }
        log.info(oids);
        // Check that all OIDs we set exist
        assertEquals("Not all QC statement Ids were included", 4, oids.size());
        assertTrue(oids.contains(ETSIQCObjectIdentifiers.id_etsi_qcs_QcCompliance.getId()));
        assertTrue(oids.contains(ETSIQCObjectIdentifiers.id_etsi_qcs_QcSSCD.getId()));
        assertTrue(oids.contains("0.4.0.1862.1.6")); // ETSIQCObjectIdentifiers.id_etsi_qcs_QcType
        assertTrue(oids.contains("0.4.0.1862.1.5")); // ETSIQCObjectIdentifiers.id_etsi_qcs_QcPds
        // Check the values we set
        assertEquals("0.4.0.1862.1.6.1", QCStatementExtension.getStatementStringValue(seq, "0.4.0.1862.1.6", 0));
        assertEquals("[http://qcs.localhost/QcPDS, en]", QCStatementExtension.getStatementStringValue(seq, "0.4.0.1862.1.5", 0));
        
    }
}

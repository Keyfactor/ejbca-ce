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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1UTF8String;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x509.qualified.ETSIQCObjectIdentifiers;
import org.bouncycastle.asn1.x509.qualified.QCStatement;
import org.bouncycastle.asn1.x509.qualified.RFC3739QCObjectIdentifiers;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.certificates.certificate.certextensions.standard.QcStatement;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.PKIDisclosureStatement;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.certificates.endentity.PSD2RoleOfPSPStatement;
import org.cesecore.certificates.util.cert.QCStatementExtension;
import org.junit.Test;

/**
 * @version $Id$
 */
@SuppressWarnings("resource")
public class QcStatementTest {
    private static Logger log = Logger.getLogger(QcStatementTest.class);
	
    @Test
    public void testQcStatement() throws CertificateExtensionException, IOException {
        CertificateProfile prof = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        prof.setUseQCStatement(true);
        prof.setUseQCEtsiQCCompliance(true);
        prof.setUseQCEtsiSignatureDevice(true);
        // QC ETSI type from eIDAS EN 319 412-5, eSign = 0.4.0.1862.1.6.1, eseal = 0.4.0.1862.1.6.2, web = 0.4.0.1862.1.6.3
        prof.setQCEtsiType(ETSIQCObjectIdentifiers.id_etsi_qct_esign.getId());
        prof.setQCEtsiPds(Arrays.asList(new PKIDisclosureStatement("http://qcs.localhost/QcPDS", "en")));
        // id-qcs-pkixQCSyntax-v2 
        prof.setUsePkixQCSyntaxV2(true);
        // (OID = 1.3.6.1.55.7.11.2) with SematicsID = 0.4.0.194121.1.1 AND 0.4.0.194121.1.2 
        // SemanticsID = "Natural Person" or "Legal Person", according to eIDAS EN 319 412-1
        prof.setQCSemanticsIds(QcStatement.id_etsi_qcs_semanticsId_Natural + "," + QcStatement.id_etsi_qcs_semanticsId_Legal);
        prof.setUseQCCountries(true);
        prof.setQCCountriesString("SE,DE,CH");
        
        QcStatement statement = new QcStatement();
        byte[] value = statement.getValueEncoded(null, null, prof, null, null, null);
        String dump = ASN1Dump.dumpAsString(new ASN1InputStream(value).readObject(), true);
        log.info(dump);
        // Hex dump can be used in Custom Certificate Extensions
        String hexEncodedQcStatements = new String(Hex.encode(value)); 
        log.info(hexEncodedQcStatements);
        // Parsing the Hex encoded QCStatements that we created above, will it parse?
        ASN1Sequence seq = (ASN1Sequence) ASN1Sequence.fromByteArray(value);
        // Dump included IDs
        // This is just a loop to get all the statement IDs in the QcStatements extension, so we can view them and count them
        ArrayList<String> oids = new ArrayList<>();
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
        assertEquals("Not all QC statement Ids were included", 7, oids.size());
        assertTrue(oids.contains(ETSIQCObjectIdentifiers.id_etsi_qcs_QcCompliance.getId()));
        assertTrue(oids.contains(ETSIQCObjectIdentifiers.id_etsi_qcs_QcSSCD.getId()));
        assertTrue(oids.contains(ETSIQCObjectIdentifiers.id_etsi_qcs_QcType.getId()));
        assertTrue(oids.contains(ETSIQCObjectIdentifiers.id_etsi_qcs_QcPds.getId()));
        // Check the values we set
        assertEquals(ETSIQCObjectIdentifiers.id_etsi_qct_esign.getId(), QCStatementExtension.getStatementStringValues(seq, ETSIQCObjectIdentifiers.id_etsi_qcs_QcType.getId(), 0).get(0));
        assertEquals("[http://qcs.localhost/QcPDS, en]", QCStatementExtension.getStatementStringValues(seq, ETSIQCObjectIdentifiers.id_etsi_qcs_QcPds.getId(), 0).get(0));
        // Check ETSI QC semantics OIDs
        assertTrue(oids.contains(RFC3739QCObjectIdentifiers.id_qcs_pkixQCSyntax_v2.getId()));
        
        final List<String> semanticOids = QCStatementExtension.getStatementStringValues(seq, RFC3739QCObjectIdentifiers.id_qcs_pkixQCSyntax_v2.getId(), 0);
        assertEquals("QC ETSI semantics OID count does not match.", 2, semanticOids.size());
        
        assertEquals("QC ETSI semantics OID does not match.", QcStatement.id_etsi_qcs_semanticsId_Natural, semanticOids.get(0));
        assertEquals("QC ETSI semantics OID does not match.", QcStatement.id_etsi_qcs_semanticsId_Legal, semanticOids.get(1));
        // Check QC ETSI legislation countries
        assertTrue(oids.contains(QcStatement.id_esi4_qcStatement_7));
        assertEquals("QC ETSI countries string does not match.", "SE", QCStatementExtension.getStatementStringValues(seq, QcStatement.id_esi4_qcStatement_7, 0).get(0));
        assertEquals("QC ETSI countries string does not match.", "DE", QCStatementExtension.getStatementStringValues(seq, QcStatement.id_esi4_qcStatement_7, 1).get(0));
        assertEquals("QC ETSI countries string does not match.", "CH", QCStatementExtension.getStatementStringValues(seq, QcStatement.id_esi4_qcStatement_7, 2).get(0));
        
        // Add PSD2 attributes
        ArrayList<PSD2RoleOfPSPStatement> roles = new ArrayList<>();
        roles.add(new PSD2RoleOfPSPStatement(QcStatement.id_etsi_psd2_role_psp_as, "PSP_AS"));
        roles.add(new PSD2RoleOfPSPStatement(QcStatement.id_etsi_psd2_role_psp_ic, "PSP_IC"));
        // THe PSD2 attributes are subject specific, so kept in ExtendedInformation
        EndEntityInformation subject = new EndEntityInformation();
        ExtendedInformation ei = new ExtendedInformation();
        subject.setExtendedInformation(ei);
        subject.getExtendedInformation().setQCEtsiPSD2RolesOfPSP(roles);
        // In the first case we haven't set to use PSD2 in the cert profile
        value = statement.getValueEncoded(null, null, prof, null, null, null);
        // Parsing the Hex encoded QCStatements that we created above, will it parse?
        seq = (ASN1Sequence) ASN1Sequence.fromByteArray(value);
        // Check that all OIDs we set exist, except PSD2 which should not be included
        // This is just a loop to get all the statement IDs in the QcStatements extension, so we can view them and count them
        oids = new ArrayList<>();
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
        assertEquals("Not all QC statement Ids were included, or PSD2 was included although it should not have been", 7, oids.size());
        assertTrue(oids.contains(ETSIQCObjectIdentifiers.id_etsi_qcs_QcCompliance.getId()));
        assertTrue(oids.contains(ETSIQCObjectIdentifiers.id_etsi_qcs_QcSSCD.getId()));
        assertTrue(oids.contains(RFC3739QCObjectIdentifiers.id_qcs_pkixQCSyntax_v2.getId()));
        assertTrue(oids.contains(ETSIQCObjectIdentifiers.id_etsi_qcs_QcType.getId()));
        assertTrue(oids.contains(ETSIQCObjectIdentifiers.id_etsi_qcs_QcPds.getId()));
        assertTrue(oids.contains(QcStatement.id_esi4_qcStatement_7));
        assertFalse(oids.contains(QcStatement.id_etsi_psd2_qcStatement));

        // Include PSD2 in the cert profile
        prof.setUseQCPSD2(true);
        try {
            value = statement.getValueEncoded(null, null, prof, null, null, null);
            fail("QCStatement with only RoleOfPSP but missing NCAName and ID should fail");
        } catch (CertificateExtensionException e) {
            // NOPMD: should throw due to missing NCAName and ID
        }
        subject.getExtendedInformation().setQCEtsiPSD2NcaName("PrimeKey Solutions AB, Solna Access, Plan A8, Sundbybergsvägen 1, SE-17173 Solna");
        try {
            value = statement.getValueEncoded(null, null, prof, null, null, null);
            fail("QCStatement with only RoleOfPSP and NCAName but missing NCAId should fail");
        } catch (CertificateExtensionException e) {
            // NOPMD: should throw due to missing NCAName and ID
        }
        subject.getExtendedInformation().setQCEtsiPSD2NcaName(null);
        subject.getExtendedInformation().setQCEtsiPSD2NcaId("SE-PK");
        try {
            value = statement.getValueEncoded(subject, null, prof, null, null, null);
            fail("QCStatement with only RoleOfPSP and NCAId but missing NCAName should fail");
        } catch (CertificateExtensionException e) {
            // NOPMD: should throw due to missing NCAName and ID
        }
        subject.getExtendedInformation().setQCEtsiPSD2NcaName("PrimeKey Solutions AB, Solna Access, Plan A8, Sundbybergsvägen 1, SE-17173 Solna");
        // PSD2 certificates should be a eSeal or web
        prof.setQCEtsiType(ETSIQCObjectIdentifiers.id_etsi_qct_eseal.getId());
        value = statement.getValueEncoded(subject, null, prof, null, null, null);
        dump = ASN1Dump.dumpAsString(new ASN1InputStream(value).readObject(), true);
        log.info(dump);
        // Hex dump can be used in Custom Certificate Extensions
        hexEncodedQcStatements = new String(Hex.encode(value)); 
        log.info(hexEncodedQcStatements);
        // Parsing the Hex encoded QCStatements that we created above, will it parse?
        seq = (ASN1Sequence) ASN1Sequence.fromByteArray(value);
        // Check that all OIDs we set exist
        // This is just a loop to get all the statement IDs in the QcStatements extension, so we can view them and count them
        oids = new ArrayList<>();
        QCStatement psd2 = null;
        for (int i = 0; i < seq.size(); i++) {
            final QCStatement qc = QCStatement.getInstance(seq.getObjectAt(i));
            final ASN1ObjectIdentifier oid = qc.getStatementId();
            if (oid != null) {
                oids.add(oid.getId());
                if (oid.getId().equals(QcStatement.id_etsi_psd2_qcStatement)) {
                    psd2 = qc;
                }
            } else {
                fail("QC statements have empty statement");
            }
        }
        log.info(oids);
        assertEquals("Not all QC statement Ids were included", 8, oids.size());
        assertTrue(oids.contains(ETSIQCObjectIdentifiers.id_etsi_qcs_QcCompliance.getId()));
        assertTrue(oids.contains(ETSIQCObjectIdentifiers.id_etsi_qcs_QcSSCD.getId()));
        assertTrue(oids.contains(RFC3739QCObjectIdentifiers.id_qcs_pkixQCSyntax_v2.getId()));
        assertTrue(oids.contains(ETSIQCObjectIdentifiers.id_etsi_qcs_QcType.getId()));
        assertTrue(oids.contains(ETSIQCObjectIdentifiers.id_etsi_qcs_QcPds.getId()));
        assertTrue(oids.contains(QcStatement.id_etsi_psd2_qcStatement));
        assertTrue(oids.contains(QcStatement.id_esi4_qcStatement_7));
        // Check the values we set (nothing was messed up due to PSD2...)
        assertEquals(ETSIQCObjectIdentifiers.id_etsi_qct_eseal.getId(), QCStatementExtension.getStatementStringValues(seq, ETSIQCObjectIdentifiers.id_etsi_qcs_QcType.getId(), 0).get(0));
        assertEquals("[http://qcs.localhost/QcPDS, en]", QCStatementExtension.getStatementStringValues(seq, ETSIQCObjectIdentifiers.id_etsi_qcs_QcPds.getId(), 0).get(0));
        // Check the PSD2 statement
        assertNotNull(psd2);
        ASN1Sequence psd2seq = ASN1Sequence.getInstance(psd2.getStatementInfo());
        assertEquals("PSD2 statement should contain 3 objects", 3, psd2seq.size());
        // The first one is the RoleOfPsp sequence
        ASN1Sequence roleseq = ASN1Sequence.getInstance(psd2seq.getObjectAt(0));
        assertEquals("We should have two RoleOfPsp", 2, roleseq.size());
        ASN1Sequence roleseqinner1 = ASN1Sequence.getInstance(roleseq.getObjectAt(0));
        ASN1ObjectIdentifier roleId1 = ASN1ObjectIdentifier.getInstance(roleseqinner1.getObjectAt(0));
        assertEquals("RoleId is not what we set", QcStatement.id_etsi_psd2_role_psp_as, roleId1.getId());        
        ASN1UTF8String roleName1 = ASN1UTF8String.getInstance(roleseqinner1.getObjectAt(1));
        assertEquals("RoleName is not what we set", "PSP_AS", roleName1.toString());        
        ASN1Sequence roleseqinner2 = ASN1Sequence.getInstance(roleseq.getObjectAt(1));
        ASN1ObjectIdentifier roleId2 = ASN1ObjectIdentifier.getInstance(roleseqinner2.getObjectAt(0));
        assertEquals("RoleId is not what we set", QcStatement.id_etsi_psd2_role_psp_ic, roleId2.getId());        
        ASN1UTF8String roleName2 = ASN1UTF8String.getInstance(roleseqinner2.getObjectAt(1));
        assertEquals("RoleName is not what we set", "PSP_IC", roleName2.toString());        
        // The second one is the NCAName
        ASN1UTF8String ncaname = ASN1UTF8String.getInstance(psd2seq.getObjectAt(1));
        assertEquals("NCAName is not what we set", "PrimeKey Solutions AB, Solna Access, Plan A8, Sundbybergsvägen 1, SE-17173 Solna", ncaname.toString());
        // The third one is the NCAId
        ASN1UTF8String ncaid = ASN1UTF8String.getInstance(psd2seq.getObjectAt(2));
        assertEquals("NCAId is not what we set", "SE-PK", ncaid.toString());
        
    }
}

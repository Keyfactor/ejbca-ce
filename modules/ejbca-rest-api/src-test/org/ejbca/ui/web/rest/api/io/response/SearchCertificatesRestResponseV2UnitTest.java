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
package org.ejbca.ui.web.rest.api.io.response;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.util.encoders.Hex;
import org.cesecore.certificates.certificate.Base64CertData;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateData;
import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.crl.RevocationReasons;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.util.dn.DNFieldsUtil;
import org.ejbca.core.model.era.RaCertificateSearchResponseV2;
import org.ejbca.ui.web.rest.api.helpers.CaInfoBuilder;
import org.ejbca.ui.web.rest.api.io.request.Pagination;
import org.ejbca.ui.web.rest.api.io.request.PaginationSummary;
import org.junit.Before;
import org.junit.Test;
import org.junit.internal.ArrayComparisonFailure;

import com.keyfactor.util.Base64;
import com.keyfactor.util.CertTools;

/**
 * A unit test class for SearchCertificatesRestResponseV2 conversion.
 */
public class SearchCertificatesRestResponseV2UnitTest {

    // given
    final X509Certificate certificate = (X509Certificate) CaInfoBuilder.testCaCertificate;
    final String fingerprint = CertTools.getFingerprintAsString(certificate);
    final String caFingerprint = fingerprint;
    final Integer certificateProfileId = CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER;
    final Integer endEntityProfileId = EndEntityConstants.NO_END_ENTITY_PROFILE;
    final Long expireDate = certificate.getNotAfter().getTime();
    final String issuerDn = certificate.getIssuerDN().getName();
    final Long notBefore = certificate.getNotBefore().getTime();
    // CertificateData revocation date and reason are 0.
    final Long revocationDate = -1L;
    final Integer revocationReason = RevocationReasons.NOT_REVOKED.getDatabaseValue();
    final String serialNumber = CertTools.getSerialNumberAsString(certificate);
    final Integer status = CertificateConstants.CERT_ACTIVE;
    // Test with other certificate.
    final String subjectAn = null; 
    final String subjectDn = certificate.getSubjectDN().getName();
    final String subjectKeyId = new String(Hex.encode(CertTools.getSubjectKeyId(certificate)));
    final String tag = "tag";
    final Integer type = CertificateConstants.CERTTYPE_ENDENTITY;
    final Long updateTime = System.currentTimeMillis();
    final String username = "testuser";        
    
    final CertificateData cd = new CertificateData(certificate, certificate.getPublicKey(), 
            username, caFingerprint, null, status, type, 
            certificateProfileId, endEntityProfileId,
            CertificateConstants.NO_CRL_PARTITION, tag, updateTime, true, true);
    
    Map<Integer, String> availableEndEntityProfiles = new HashMap<>();
    Map<Integer, String> availableCertificateProfiles = new HashMap<>();
    
    @Before
    public void init() {
        availableEndEntityProfiles.put(EndEntityConstants.NO_END_ENTITY_PROFILE, "EMPTY");
        availableCertificateProfiles.put(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, "ENDUSER");
    }
    
    @Test
    public void testConvertRaCertificateSearchResponse() throws CertificateEncodingException, CertificateParsingException {
     
        // given
        final List<CertificateDataWrapper> list = Collections.singletonList(new CertificateDataWrapper(certificate, cd, null));
        final RaCertificateSearchResponseV2 raResponse = new RaCertificateSearchResponseV2();
        raResponse.setCdws(list);
        raResponse.setTotalCount(list.size());
        
        // when
        final SearchCertificatesRestResponseV2 restResponse = 
                SearchCertificatesRestResponseV2.converter().toRestResponse(raResponse, new Pagination(10, 1), 
                        availableEndEntityProfiles, availableCertificateProfiles);
        
        // then
        assertPaginationSummary(restResponse, list.size());
        assertCertificateResultList(restResponse);
    }
    
    @Test
    public void testConvertRaCertificateSearchResponseWithBase64Cert() throws CertificateEncodingException, CertificateParsingException {
     
        // given
        final Base64CertData base64CertData = new Base64CertData(certificate);
        final List<CertificateDataWrapper> list = new ArrayList<>();
        // Test both -> same result.
        list.add(new CertificateDataWrapper(null, cd, base64CertData));
        list.add(new CertificateDataWrapper(certificate, cd, base64CertData));
        
        final RaCertificateSearchResponseV2 raResponse = new RaCertificateSearchResponseV2();
        raResponse.setCdws(list);
        raResponse.setTotalCount(list.size());
        
        // when
        final SearchCertificatesRestResponseV2 restResponse = 
                SearchCertificatesRestResponseV2.converter().toRestResponse(raResponse, new Pagination(10, 1),
                        availableEndEntityProfiles, availableCertificateProfiles);
        
        // then
        assertPaginationSummary(restResponse, list.size());
        assertCertificateResultList(restResponse);
    }

    @Test
    public void testConvertRaCertificateSearchResponseWhenCurrentPageNegativeOne() throws CertificateEncodingException, CertificateParsingException {

        // given
        final Long total = 77l;
        final List<CertificateDataWrapper> list = new ArrayList<>();
        final RaCertificateSearchResponseV2 raResponse = new RaCertificateSearchResponseV2();
        raResponse.setCdws(list);
        raResponse.setTotalCount(total);

        // when
        final int currentPage = -1;
        final SearchCertificatesRestResponseV2 restResponse = 
                SearchCertificatesRestResponseV2.converter().toRestResponse(
                        raResponse, new Pagination(10, currentPage), availableEndEntityProfiles, availableCertificateProfiles);

        // then
        final PaginationSummary summary = restResponse.getPaginationSummary();
        Long totalCount = summary.getTotalCerts();
        List certificates = restResponse.getCertificates();
        assertNotNull("PaginationSummary must not be null.", summary);
        assertEquals("Total count does not match.", total, totalCount);
        assertNotNull("List of certificates must not be null.", certificates);
        assertTrue("Certificates list is not empty.", certificates.isEmpty());
    }
    
    private final void assertPaginationSummary(final SearchCertificatesRestResponseV2 response, final int listSize) {
        final PaginationSummary summary = response.getPaginationSummary();
        assertNotNull("PaginationSummary must not be null.", summary); 
        assertEquals("Total count does not match.", listSize, (long) summary.getTotalCerts());
        assertNotNull("List of certificates must not be null.", response.getCertificates());
        assertEquals("Size of certificates list does not match.", listSize, response.getCertificates().size());
    }
    
    private final void assertCertificateResultList(final SearchCertificatesRestResponseV2 response) throws CertificateEncodingException, ArrayComparisonFailure {
        for (CertificateRestResponseV2 payload : response.getCertificates()) {
            assertEquals("Certificate fingerprint does not match.", fingerprint, payload.getFingerprint());
            assertEquals("CA certificate fingerprint does not match.", caFingerprint, payload.getCaFingerprint());
            assertEquals("Certificate profile ID does not match.", (Integer) CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, payload.getCertificateProfileId());
            assertEquals("End entity profile ID does not match.", (Integer) EndEntityConstants.NO_END_ENTITY_PROFILE, payload.getEndEntityProfileId());
            assertEquals("Certificate profile name does not match.", "ENDUSER", payload.getCertificateProfile());
            assertEquals("End entity profile name does not match.", "EMPTY", payload.getEndEntityProfile());
            assertEquals("Expire date does not match.", expireDate, payload.getExpireDate());
            assertEquals("Issuer DN does not match.", DNFieldsUtil.dnStringToMap(issuerDn), DNFieldsUtil.dnStringToMap(payload.getIssuerDN()));
            assertEquals("Not before does not match.", notBefore, payload.getNotBefore());
            assertEquals("Revocation date does not match.", revocationDate, payload.getRevocationDate());
            assertEquals("Revocation reason does not match.", revocationReason, payload.getRevocationReason());
            assertEquals("Serial number does not match.", serialNumber, payload.getSerialNumber());
            assertEquals("Subject AN does not match.", subjectAn, payload.getSubjectAltName());
            assertEquals("Subject DN does not match.", DNFieldsUtil.dnStringToMap(subjectDn), DNFieldsUtil.dnStringToMap(payload.getSubjectDN()));
            assertEquals("Subject key ID does not match.", subjectKeyId, payload.getSubjectKeyId());
            assertEquals("Tag does not match.", tag, payload.getTag());
            assertEquals("Type does not match.", type, payload.getType());
            assertEquals("Update time does not match.", updateTime, payload.getUpdateTime());
            assertArrayEquals("Certificate does not match.", Base64.encode(certificate.getEncoded()), payload.getCertificate());
            assertEquals("Username does not match.", username, payload.getUsername());
        }
    }

}

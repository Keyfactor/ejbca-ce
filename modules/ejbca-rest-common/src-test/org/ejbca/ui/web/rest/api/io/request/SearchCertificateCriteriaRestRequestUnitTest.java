/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ui.web.rest.api.io.request;

import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.junit.Test;

import static org.ejbca.ui.web.rest.api.io.request.SearchCertificateCriteriaRestRequest.CertificateStatus;
import static org.ejbca.ui.web.rest.api.io.request.SearchCertificateCriteriaRestRequest.CriteriaOperation;
import static org.ejbca.ui.web.rest.api.io.request.SearchCertificateCriteriaRestRequest.CriteriaProperty;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * A unit test class for SearchCertificateCriteriaRestRequest.
 *
 * @version $Id: SearchCertificateCriteriaRestRequestUnitTest.java 29504 2018-07-17 17:55:12Z andrey_s_helmes $
 */
public class SearchCertificateCriteriaRestRequestUnitTest {

    @Test
    public void shouldProperlyDefineStringOperationsSetForCriteriaProperty() {
        // given
        // when
        // then
        assertEquals("Should have proper enum set.", 2, CriteriaProperty.STRING_PROPERTIES().size());
        assertTrue("Should have proper enum set.", CriteriaProperty.STRING_PROPERTIES().contains(CriteriaProperty.QUERY));
        assertTrue("Should have proper enum set.", CriteriaProperty.STRING_PROPERTIES().contains(CriteriaProperty.STATUS));
    }

    @Test
    public void shouldProperlyDefineDateOperationsSetForCriteriaProperty() {
        // given
        // when
        // then
        assertEquals("Should have proper enum set.", 3, CriteriaProperty.DATE_PROPERTIES().size());
        assertTrue("Should have proper enum set.", CriteriaProperty.DATE_PROPERTIES().contains(CriteriaProperty.ISSUED_DATE));
        assertTrue("Should have proper enum set.", CriteriaProperty.DATE_PROPERTIES().contains(CriteriaProperty.EXPIRE_DATE));
        assertTrue("Should have proper enum set.", CriteriaProperty.DATE_PROPERTIES().contains(CriteriaProperty.REVOCATION_DATE));
    }

    @Test
    public void shouldProperlyDefineStringOperationsSetForCriteriaOperation() {
        // given
        // when
        // then
        assertEquals("Should have proper enum set.", 2, CriteriaOperation.STRING_OPERATIONS().size());
        assertTrue("Should have proper enum set.", CriteriaOperation.STRING_OPERATIONS().contains(CriteriaOperation.EQUAL));
        assertTrue("Should have proper enum set.", CriteriaOperation.STRING_OPERATIONS().contains(CriteriaOperation.LIKE));
    }

    @Test
    public void shouldProperlyDefineDateOperationsSetForCriteriaOperation() {
        // given
        // when
        // then
        assertEquals("Should have proper enum set.", 2, CriteriaOperation.DATE_OPERATIONS().size());
        assertTrue("Should have proper enum set.", CriteriaOperation.DATE_OPERATIONS().contains(CriteriaOperation.AFTER));
        assertTrue("Should have proper enum set.", CriteriaOperation.DATE_OPERATIONS().contains(CriteriaOperation.BEFORE));
    }

    @Test
    public void shouldProperlyDefineRevocationReasonsSetForCertificateStatus() {
        // given
        // when
        // then
        assertEquals("Should have proper enum set.", 10, CertificateStatus.REVOCATION_REASONS().size());
        assertTrue("Should have proper enum set.", CertificateStatus.REVOCATION_REASONS().contains(CertificateStatus.REVOCATION_REASON_AACOMPROMISE));
        assertTrue("Should have proper enum set.", CertificateStatus.REVOCATION_REASONS().contains(CertificateStatus.REVOCATION_REASON_AFFILIATIONCHANGED));
        assertTrue("Should have proper enum set.", CertificateStatus.REVOCATION_REASONS().contains(CertificateStatus.REVOCATION_REASON_CACOMPROMISE));
        assertTrue("Should have proper enum set.", CertificateStatus.REVOCATION_REASONS().contains(CertificateStatus.REVOCATION_REASON_CERTIFICATEHOLD));
        assertTrue("Should have proper enum set.", CertificateStatus.REVOCATION_REASONS().contains(CertificateStatus.REVOCATION_REASON_CESSATIONOFOPERATION));
        assertTrue("Should have proper enum set.", CertificateStatus.REVOCATION_REASONS().contains(CertificateStatus.REVOCATION_REASON_KEYCOMPROMISE));
        assertTrue("Should have proper enum set.", CertificateStatus.REVOCATION_REASONS().contains(CertificateStatus.REVOCATION_REASON_PRIVILEGESWITHDRAWN));
        assertTrue("Should have proper enum set.", CertificateStatus.REVOCATION_REASONS().contains(CertificateStatus.REVOCATION_REASON_REMOVEFROMCRL));
        assertTrue("Should have proper enum set.", CertificateStatus.REVOCATION_REASONS().contains(CertificateStatus.REVOCATION_REASON_SUPERSEDED));
        assertTrue("Should have proper enum set.", CertificateStatus.REVOCATION_REASONS().contains(CertificateStatus.REVOCATION_REASON_UNSPECIFIED));
    }

    @Test
    public void shouldProperlyDefineIntegerConstantForCertificateStatus() {
        // given
        // when
        // then
        assertEquals("Should have proper enum set.", CertificateConstants.CERT_ACTIVE, CertificateStatus.CERT_ACTIVE.getStatusValue());
        assertEquals("Should have proper enum set.", CertificateConstants.CERT_REVOKED, CertificateStatus.CERT_REVOKED.getStatusValue());
        assertEquals("Should have proper enum set.", RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED, CertificateStatus.REVOCATION_REASON_UNSPECIFIED.getStatusValue());
        assertEquals("Should have proper enum set.", RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE, CertificateStatus.REVOCATION_REASON_KEYCOMPROMISE.getStatusValue());
        assertEquals("Should have proper enum set.", RevokedCertInfo.REVOCATION_REASON_CACOMPROMISE, CertificateStatus.REVOCATION_REASON_CACOMPROMISE.getStatusValue());
        assertEquals("Should have proper enum set.", RevokedCertInfo.REVOCATION_REASON_AFFILIATIONCHANGED, CertificateStatus.REVOCATION_REASON_AFFILIATIONCHANGED.getStatusValue());
        assertEquals("Should have proper enum set.", RevokedCertInfo.REVOCATION_REASON_SUPERSEDED, CertificateStatus.REVOCATION_REASON_SUPERSEDED.getStatusValue());
        assertEquals("Should have proper enum set.", RevokedCertInfo.REVOCATION_REASON_CESSATIONOFOPERATION, CertificateStatus.REVOCATION_REASON_CESSATIONOFOPERATION.getStatusValue());
        assertEquals("Should have proper enum set.", RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD, CertificateStatus.REVOCATION_REASON_CERTIFICATEHOLD.getStatusValue());
        assertEquals("Should have proper enum set.", RevokedCertInfo.REVOCATION_REASON_REMOVEFROMCRL, CertificateStatus.REVOCATION_REASON_REMOVEFROMCRL.getStatusValue());
        assertEquals("Should have proper enum set.", RevokedCertInfo.REVOCATION_REASON_PRIVILEGESWITHDRAWN, CertificateStatus.REVOCATION_REASON_PRIVILEGESWITHDRAWN.getStatusValue());
        assertEquals("Should have proper enum set.", RevokedCertInfo.REVOCATION_REASON_AACOMPROMISE, CertificateStatus.REVOCATION_REASON_AACOMPROMISE.getStatusValue());
    }
}

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
 * @version $Id: SearchCertificateCriteriaRestRequestUnitTest.java 29436 2018-07-03 11:12:13Z andrey_s_helmes $
 */
public class SearchCertificateCriteriaRestRequestUnitTest {

    @Test
    public void shouldProperlyDefineStringOperationsSetForCriteriaProperty() {
        // given
        // when
        // then
        assertEquals(2, CriteriaProperty.STRING_PROPERTIES().size());
        assertTrue(CriteriaProperty.STRING_PROPERTIES().contains(CriteriaProperty.QUERY));
        assertTrue(CriteriaProperty.STRING_PROPERTIES().contains(CriteriaProperty.STATUS));
    }

    @Test
    public void shouldProperlyDefineIntegerOperationsSetForCriteriaProperty() {
        // given
        // when
        // then
        assertEquals(3, CriteriaProperty.INTEGER_PROPERTIES().size());
        assertTrue(CriteriaProperty.INTEGER_PROPERTIES().contains(CriteriaProperty.END_ENTITY_PROFILE));
        assertTrue(CriteriaProperty.INTEGER_PROPERTIES().contains(CriteriaProperty.CERTIFICATE_PROFILE));
        assertTrue(CriteriaProperty.INTEGER_PROPERTIES().contains(CriteriaProperty.CA));
    }

    @Test
    public void shouldProperlyDefineDateOperationsSetForCriteriaProperty() {
        // given
        // when
        // then
        assertEquals(3, CriteriaProperty.DATE_PROPERTIES().size());
        assertTrue(CriteriaProperty.DATE_PROPERTIES().contains(CriteriaProperty.ISSUED_DATE));
        assertTrue(CriteriaProperty.DATE_PROPERTIES().contains(CriteriaProperty.EXPIRE_DATE));
        assertTrue(CriteriaProperty.DATE_PROPERTIES().contains(CriteriaProperty.REVOCATION_DATE));
    }

    @Test
    public void shouldProperlyDefineStringOperationsSetForCriteriaOperation() {
        // given
        // when
        // then
        assertEquals(2, CriteriaOperation.STRING_OPERATIONS().size());
        assertTrue(CriteriaOperation.STRING_OPERATIONS().contains(CriteriaOperation.EQUAL));
        assertTrue(CriteriaOperation.STRING_OPERATIONS().contains(CriteriaOperation.LIKE));
    }

    @Test
    public void shouldProperlyDefineIntegerOperationsSetForCriteriaOperation() {
        // given
        // when
        // then
        assertEquals(1, CriteriaOperation.INTEGER_OPERATIONS().size());
        assertTrue(CriteriaOperation.INTEGER_OPERATIONS().contains(CriteriaOperation.EQUAL));
    }

    @Test
    public void shouldProperlyDefineDateOperationsSetForCriteriaOperation() {
        // given
        // when
        // then
        assertEquals(2, CriteriaOperation.DATE_OPERATIONS().size());
        assertTrue(CriteriaOperation.DATE_OPERATIONS().contains(CriteriaOperation.AFTER));
        assertTrue(CriteriaOperation.DATE_OPERATIONS().contains(CriteriaOperation.BEFORE));
    }

    @Test
    public void shouldProperlyDefineRevocationReasonsSetForCertificateStatus() {
        // given
        // when
        // then
        assertEquals(10, CertificateStatus.REVOCATION_REASONS().size());
        assertTrue(CertificateStatus.REVOCATION_REASONS().contains(CertificateStatus.REVOCATION_REASON_AACOMPROMISE));
        assertTrue(CertificateStatus.REVOCATION_REASONS().contains(CertificateStatus.REVOCATION_REASON_AFFILIATIONCHANGED));
        assertTrue(CertificateStatus.REVOCATION_REASONS().contains(CertificateStatus.REVOCATION_REASON_CACOMPROMISE));
        assertTrue(CertificateStatus.REVOCATION_REASONS().contains(CertificateStatus.REVOCATION_REASON_CERTIFICATEHOLD));
        assertTrue(CertificateStatus.REVOCATION_REASONS().contains(CertificateStatus.REVOCATION_REASON_CESSATIONOFOPERATION));
        assertTrue(CertificateStatus.REVOCATION_REASONS().contains(CertificateStatus.REVOCATION_REASON_KEYCOMPROMISE));
        assertTrue(CertificateStatus.REVOCATION_REASONS().contains(CertificateStatus.REVOCATION_REASON_PRIVILEGESWITHDRAWN));
        assertTrue(CertificateStatus.REVOCATION_REASONS().contains(CertificateStatus.REVOCATION_REASON_REMOVEFROMCRL));
        assertTrue(CertificateStatus.REVOCATION_REASONS().contains(CertificateStatus.REVOCATION_REASON_SUPERSEDED));
        assertTrue(CertificateStatus.REVOCATION_REASONS().contains(CertificateStatus.REVOCATION_REASON_UNSPECIFIED));
    }

    @Test
    public void shouldProperlyDefineIntegerConstantForCertificateStatus() {
        // given
        // when
        // then
        assertEquals(CertificateConstants.CERT_ACTIVE, CertificateStatus.CERT_ACTIVE.getStatusValue());
        assertEquals(CertificateConstants.CERT_REVOKED, CertificateStatus.CERT_REVOKED.getStatusValue());
        assertEquals(RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED, CertificateStatus.REVOCATION_REASON_UNSPECIFIED.getStatusValue());
        assertEquals(RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE, CertificateStatus.REVOCATION_REASON_KEYCOMPROMISE.getStatusValue());
        assertEquals(RevokedCertInfo.REVOCATION_REASON_CACOMPROMISE, CertificateStatus.REVOCATION_REASON_CACOMPROMISE.getStatusValue());
        assertEquals(RevokedCertInfo.REVOCATION_REASON_AFFILIATIONCHANGED, CertificateStatus.REVOCATION_REASON_AFFILIATIONCHANGED.getStatusValue());
        assertEquals(RevokedCertInfo.REVOCATION_REASON_SUPERSEDED, CertificateStatus.REVOCATION_REASON_SUPERSEDED.getStatusValue());
        assertEquals(RevokedCertInfo.REVOCATION_REASON_CESSATIONOFOPERATION, CertificateStatus.REVOCATION_REASON_CESSATIONOFOPERATION.getStatusValue());
        assertEquals(RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD, CertificateStatus.REVOCATION_REASON_CERTIFICATEHOLD.getStatusValue());
        assertEquals(RevokedCertInfo.REVOCATION_REASON_REMOVEFROMCRL, CertificateStatus.REVOCATION_REASON_REMOVEFROMCRL.getStatusValue());
        assertEquals(RevokedCertInfo.REVOCATION_REASON_PRIVILEGESWITHDRAWN, CertificateStatus.REVOCATION_REASON_PRIVILEGESWITHDRAWN.getStatusValue());
        assertEquals(RevokedCertInfo.REVOCATION_REASON_AACOMPROMISE, CertificateStatus.REVOCATION_REASON_AACOMPROMISE.getStatusValue());
    }
}

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

import org.ejbca.core.model.era.RaCertificateSearchRequest;
import org.ejbca.ui.web.rest.api.exception.RestException;
import org.junit.Test;

import java.util.Collections;

import static org.ejbca.ui.web.rest.api.io.request.SearchCertificateCriteriaRestRequest.CertificateStatus;
import static org.ejbca.ui.web.rest.api.io.request.SearchCertificateCriteriaRestRequest.CriteriaOperation;
import static org.ejbca.ui.web.rest.api.io.request.SearchCertificateCriteriaRestRequest.CriteriaProperty;

import static org.junit.Assert.assertEquals;

/**
 * A unit test class for SearchCertificatesRestRequest.
 *
 * @version $Id: SearchCertificatesRestRequestUnitTest.java 29504 2018-07-17 17:55:12Z andrey_s_helmes $
 */
public class SearchCertificatesRestRequestUnitTest {

    @Test
    public void shouldProperlyConvertSearchCertificatesRestRequestWithQUERYPropertyAndEQUALOperation() throws RestException {
        // given
        final int expectedPageNumber = 0;
        final int expectedMaxNumberOfResults = 10;
        final String expectedSearchString = "A";
        final boolean expectedSearchMatchExact = true;
        final SearchCertificateCriteriaRestRequest searchCertificateCriteriaRestRequest = SearchCertificateCriteriaRestRequest.builder()
                .property(CriteriaProperty.QUERY.name())
                .value(expectedSearchString)
                .operation(CriteriaOperation.EQUAL.name())
                .build();
        final SearchCertificatesRestRequest searchCertificatesRestRequest = SearchCertificatesRestRequest.builder()
                .maxNumberOfResults(expectedMaxNumberOfResults)
                .criteria(Collections.singletonList(searchCertificateCriteriaRestRequest))
                .build();
        // when
        final RaCertificateSearchRequest actualRaCertificateSearchRequest = SearchCertificatesRestRequest.converter().toEntity(searchCertificatesRestRequest);
        // then
        assertEquals("Should properly convert.", expectedMaxNumberOfResults, actualRaCertificateSearchRequest.getMaxResults());
        assertEquals("Should properly convert.", expectedPageNumber, actualRaCertificateSearchRequest.getPageNumber());
        assertEquals("Should properly convert.", 0, actualRaCertificateSearchRequest.getEepIds().size());
        assertEquals("Should properly convert.", 0, actualRaCertificateSearchRequest.getCpIds().size());
        assertEquals("Should properly convert.", 0, actualRaCertificateSearchRequest.getCaIds().size());
        assertEquals("Should properly convert.", expectedSearchString, actualRaCertificateSearchRequest.getSubjectDnSearchString());
        assertEquals("Should properly convert.", expectedSearchMatchExact, actualRaCertificateSearchRequest.isSubjectDnSearchExact());
        assertEquals("Should properly convert.", expectedSearchString, actualRaCertificateSearchRequest.getSubjectAnSearchString());
        assertEquals("Should properly convert.", expectedSearchMatchExact, actualRaCertificateSearchRequest.isSubjectAnSearchExact());
        assertEquals("Should properly convert.", expectedSearchString, actualRaCertificateSearchRequest.getUsernameSearchString());
        assertEquals("Should properly convert.", expectedSearchMatchExact, actualRaCertificateSearchRequest.isUsernameSearchExact());
        assertEquals("Should properly convert.", "", actualRaCertificateSearchRequest.getSerialNumberSearchStringFromDec());
        assertEquals("Should properly convert.", "", actualRaCertificateSearchRequest.getSerialNumberSearchStringFromHex());
        assertEquals("Should properly convert.", 0L, actualRaCertificateSearchRequest.getIssuedAfter());
        assertEquals("Should properly convert.", Long.MAX_VALUE, actualRaCertificateSearchRequest.getIssuedBefore());
        assertEquals("Should properly convert.", 0L, actualRaCertificateSearchRequest.getExpiresAfter());
        assertEquals("Should properly convert.", Long.MAX_VALUE, actualRaCertificateSearchRequest.getExpiresBefore());
        assertEquals("Should properly convert.", 0L, actualRaCertificateSearchRequest.getRevokedAfter());
        assertEquals("Should properly convert.", Long.MAX_VALUE, actualRaCertificateSearchRequest.getRevokedBefore());
        assertEquals("Should properly convert.", 0, actualRaCertificateSearchRequest.getStatuses().size());
        assertEquals("Should properly convert.", 0, actualRaCertificateSearchRequest.getRevocationReasons().size());
    }

    @Test
    public void shouldProperlyConvertSearchCertificatesRestRequestWithQUERYPropertyAndLIKEOperation() throws RestException {
        // given
        final int expectedPageNumber = 0;
        final int expectedMaxNumberOfResults = 10;
        final String expectedSearchString = "B";
        final boolean expectedSearchMatchExact = false;
        final SearchCertificateCriteriaRestRequest searchCertificateCriteriaRestRequest = SearchCertificateCriteriaRestRequest.builder()
                .property(CriteriaProperty.QUERY.name())
                .value(expectedSearchString)
                .operation(CriteriaOperation.LIKE.name())
                .build();
        final SearchCertificatesRestRequest searchCertificatesRestRequest = SearchCertificatesRestRequest.builder()
                .maxNumberOfResults(expectedMaxNumberOfResults)
                .criteria(Collections.singletonList(searchCertificateCriteriaRestRequest))
                .build();
        // when
        final RaCertificateSearchRequest actualRaCertificateSearchRequest = SearchCertificatesRestRequest.converter().toEntity(searchCertificatesRestRequest);
        // then
        assertEquals("Should properly convert.", expectedMaxNumberOfResults, actualRaCertificateSearchRequest.getMaxResults());
        assertEquals("Should properly convert.", expectedPageNumber, actualRaCertificateSearchRequest.getPageNumber());
        assertEquals("Should properly convert.", 0, actualRaCertificateSearchRequest.getEepIds().size());
        assertEquals("Should properly convert.", 0, actualRaCertificateSearchRequest.getCpIds().size());
        assertEquals("Should properly convert.", 0, actualRaCertificateSearchRequest.getCaIds().size());
        assertEquals("Should properly convert.", expectedSearchString, actualRaCertificateSearchRequest.getSubjectDnSearchString());
        assertEquals("Should properly convert.", expectedSearchMatchExact, actualRaCertificateSearchRequest.isSubjectDnSearchExact());
        assertEquals("Should properly convert.", expectedSearchString, actualRaCertificateSearchRequest.getSubjectAnSearchString());
        assertEquals("Should properly convert.", expectedSearchMatchExact, actualRaCertificateSearchRequest.isSubjectAnSearchExact());
        assertEquals("Should properly convert.", expectedSearchString, actualRaCertificateSearchRequest.getUsernameSearchString());
        assertEquals("Should properly convert.", expectedSearchMatchExact, actualRaCertificateSearchRequest.isUsernameSearchExact());
        assertEquals("Should properly convert.", "", actualRaCertificateSearchRequest.getSerialNumberSearchStringFromDec());
        assertEquals("Should properly convert.", "", actualRaCertificateSearchRequest.getSerialNumberSearchStringFromHex());
        assertEquals("Should properly convert.", 0L, actualRaCertificateSearchRequest.getIssuedAfter());
        assertEquals("Should properly convert.", Long.MAX_VALUE, actualRaCertificateSearchRequest.getIssuedBefore());
        assertEquals("Should properly convert.", 0L, actualRaCertificateSearchRequest.getExpiresAfter());
        assertEquals("Should properly convert.", Long.MAX_VALUE, actualRaCertificateSearchRequest.getExpiresBefore());
        assertEquals("Should properly convert.", 0L, actualRaCertificateSearchRequest.getRevokedAfter());
        assertEquals("Should properly convert.", Long.MAX_VALUE, actualRaCertificateSearchRequest.getRevokedBefore());
        assertEquals("Should properly convert.", 0, actualRaCertificateSearchRequest.getStatuses().size());
        assertEquals("Should properly convert.", 0, actualRaCertificateSearchRequest.getRevocationReasons().size());
    }

    @Test
    public void shouldProperlyConvertSearchCertificatesRestRequestWithEND_ENTITY_PROFILEPropertyAndEQUALOperation() throws RestException {
        // given
        final int expectedPageNumber = 0;
        final int expectedMaxNumberOfResults = 10;
        final String expectedSearchString = "";
        final Integer expectedEndEntityProfileId = 111;
        final boolean expectedSearchMatchExact = false;
        final SearchCertificateCriteriaRestRequest searchCertificateCriteriaRestRequest = SearchCertificateCriteriaRestRequest.builder()
                .property(CriteriaProperty.END_ENTITY_PROFILE.name())
                .value(expectedEndEntityProfileId.toString())
                .operation(CriteriaOperation.EQUAL.name())
                .identifier(expectedEndEntityProfileId)
                .build();
        final SearchCertificatesRestRequest searchCertificatesRestRequest = SearchCertificatesRestRequest.builder()
                .maxNumberOfResults(expectedMaxNumberOfResults)
                .criteria(Collections.singletonList(searchCertificateCriteriaRestRequest))
                .build();
        // when
        final RaCertificateSearchRequest actualRaCertificateSearchRequest = SearchCertificatesRestRequest.converter().toEntity(searchCertificatesRestRequest);
        // then
        assertEquals("Should properly convert.", expectedMaxNumberOfResults, actualRaCertificateSearchRequest.getMaxResults());
        assertEquals("Should properly convert.", expectedPageNumber, actualRaCertificateSearchRequest.getPageNumber());
        assertEquals(1, actualRaCertificateSearchRequest.getEepIds().size());
        assertEquals("Should properly convert.", expectedEndEntityProfileId, actualRaCertificateSearchRequest.getEepIds().get(0));
        assertEquals("Should properly convert.", 0, actualRaCertificateSearchRequest.getCpIds().size());
        assertEquals("Should properly convert.", 0, actualRaCertificateSearchRequest.getCaIds().size());
        assertEquals("Should properly convert.", expectedSearchString, actualRaCertificateSearchRequest.getSubjectDnSearchString());
        assertEquals("Should properly convert.", expectedSearchMatchExact, actualRaCertificateSearchRequest.isSubjectDnSearchExact());
        assertEquals("Should properly convert.", expectedSearchString, actualRaCertificateSearchRequest.getSubjectAnSearchString());
        assertEquals("Should properly convert.", expectedSearchMatchExact, actualRaCertificateSearchRequest.isSubjectAnSearchExact());
        assertEquals("Should properly convert.", expectedSearchString, actualRaCertificateSearchRequest.getUsernameSearchString());
        assertEquals("Should properly convert.", expectedSearchMatchExact, actualRaCertificateSearchRequest.isUsernameSearchExact());
        assertEquals("Should properly convert.", "", actualRaCertificateSearchRequest.getSerialNumberSearchStringFromDec());
        assertEquals("Should properly convert.", "", actualRaCertificateSearchRequest.getSerialNumberSearchStringFromHex());
        assertEquals("Should properly convert.", 0L, actualRaCertificateSearchRequest.getIssuedAfter());
        assertEquals("Should properly convert.", Long.MAX_VALUE, actualRaCertificateSearchRequest.getIssuedBefore());
        assertEquals("Should properly convert.", 0L, actualRaCertificateSearchRequest.getExpiresAfter());
        assertEquals(Long.MAX_VALUE, actualRaCertificateSearchRequest.getExpiresBefore());
        assertEquals("Should properly convert.", 0L, actualRaCertificateSearchRequest.getRevokedAfter());
        assertEquals("Should properly convert.", Long.MAX_VALUE, actualRaCertificateSearchRequest.getRevokedBefore());
        assertEquals("Should properly convert.", 0, actualRaCertificateSearchRequest.getStatuses().size());
        assertEquals("Should properly convert.", 0, actualRaCertificateSearchRequest.getRevocationReasons().size());
    }

    @Test
    public void shouldProperlyConvertSearchCertificatesRestRequestWithCERTIFICATE_PROFILEPropertyAndEQUALOperation() throws RestException {
        // given
        final int expectedPageNumber = 0;
        final int expectedMaxNumberOfResults = 10;
        final String expectedSearchString = "";
        final Integer expectedCertificateProfileId = 111;
        final boolean expectedSearchMatchExact = false;
        final SearchCertificateCriteriaRestRequest searchCertificateCriteriaRestRequest = SearchCertificateCriteriaRestRequest.builder()
                .property(CriteriaProperty.CERTIFICATE_PROFILE.name())
                .value(expectedCertificateProfileId.toString())
                .operation(CriteriaOperation.EQUAL.name())
                .identifier(expectedCertificateProfileId)
                .build();
        final SearchCertificatesRestRequest searchCertificatesRestRequest = SearchCertificatesRestRequest.builder()
                .maxNumberOfResults(expectedMaxNumberOfResults)
                .criteria(Collections.singletonList(searchCertificateCriteriaRestRequest))
                .build();
        // when
        final RaCertificateSearchRequest actualRaCertificateSearchRequest = SearchCertificatesRestRequest.converter().toEntity(searchCertificatesRestRequest);
        // then
        assertEquals("Should properly convert.", expectedMaxNumberOfResults, actualRaCertificateSearchRequest.getMaxResults());
        assertEquals("Should properly convert.", expectedPageNumber, actualRaCertificateSearchRequest.getPageNumber());
        assertEquals("Should properly convert.", 0, actualRaCertificateSearchRequest.getEepIds().size());
        assertEquals("Should properly convert.", 1, actualRaCertificateSearchRequest.getCpIds().size());
        assertEquals("Should properly convert.", expectedCertificateProfileId, actualRaCertificateSearchRequest.getCpIds().get(0));
        assertEquals("Should properly convert.", 0, actualRaCertificateSearchRequest.getCaIds().size());
        assertEquals("Should properly convert.", expectedSearchString, actualRaCertificateSearchRequest.getSubjectDnSearchString());
        assertEquals("Should properly convert.", expectedSearchMatchExact, actualRaCertificateSearchRequest.isSubjectDnSearchExact());
        assertEquals("Should properly convert.", expectedSearchString, actualRaCertificateSearchRequest.getSubjectAnSearchString());
        assertEquals("Should properly convert.", expectedSearchMatchExact, actualRaCertificateSearchRequest.isSubjectAnSearchExact());
        assertEquals("Should properly convert.", expectedSearchString, actualRaCertificateSearchRequest.getUsernameSearchString());
        assertEquals("Should properly convert.", expectedSearchMatchExact, actualRaCertificateSearchRequest.isUsernameSearchExact());
        assertEquals("Should properly convert.", "", actualRaCertificateSearchRequest.getSerialNumberSearchStringFromDec());
        assertEquals("Should properly convert.", "", actualRaCertificateSearchRequest.getSerialNumberSearchStringFromHex());
        assertEquals("Should properly convert.", 0L, actualRaCertificateSearchRequest.getIssuedAfter());
        assertEquals("Should properly convert.", Long.MAX_VALUE, actualRaCertificateSearchRequest.getIssuedBefore());
        assertEquals("Should properly convert.", 0L, actualRaCertificateSearchRequest.getExpiresAfter());
        assertEquals("Should properly convert.", Long.MAX_VALUE, actualRaCertificateSearchRequest.getExpiresBefore());
        assertEquals("Should properly convert.", 0L, actualRaCertificateSearchRequest.getRevokedAfter());
        assertEquals("Should properly convert.", Long.MAX_VALUE, actualRaCertificateSearchRequest.getRevokedBefore());
        assertEquals("Should properly convert.", 0, actualRaCertificateSearchRequest.getStatuses().size());
        assertEquals("Should properly convert.", 0, actualRaCertificateSearchRequest.getRevocationReasons().size());
    }

    @Test
    public void shouldProperlyConvertSearchCertificatesRestRequestWithCAPropertyAndEQUALOperation() throws RestException {
        // given
        final int expectedPageNumber = 0;
        final int expectedMaxNumberOfResults = 10;
        final String expectedSearchString = "";
        final Integer expectedCAId = 111;
        final boolean expectedSearchMatchExact = false;
        final SearchCertificateCriteriaRestRequest searchCertificateCriteriaRestRequest = SearchCertificateCriteriaRestRequest.builder()
                .property(CriteriaProperty.CA.name())
                .value(expectedCAId.toString())
                .operation(CriteriaOperation.EQUAL.name())
                .identifier(expectedCAId)
                .build();
        final SearchCertificatesRestRequest searchCertificatesRestRequest = SearchCertificatesRestRequest.builder()
                .maxNumberOfResults(expectedMaxNumberOfResults)
                .criteria(Collections.singletonList(searchCertificateCriteriaRestRequest))
                .build();
        // when
        final RaCertificateSearchRequest actualRaCertificateSearchRequest = SearchCertificatesRestRequest.converter().toEntity(searchCertificatesRestRequest);
        // then
        assertEquals("Should properly convert.", expectedMaxNumberOfResults, actualRaCertificateSearchRequest.getMaxResults());
        assertEquals("Should properly convert.", expectedPageNumber, actualRaCertificateSearchRequest.getPageNumber());
        assertEquals("Should properly convert.", 0, actualRaCertificateSearchRequest.getEepIds().size());
        assertEquals("Should properly convert.", 0, actualRaCertificateSearchRequest.getCpIds().size());
        assertEquals("Should properly convert.", 1, actualRaCertificateSearchRequest.getCaIds().size());
        assertEquals("Should properly convert.", expectedCAId, actualRaCertificateSearchRequest.getCaIds().get(0));
        assertEquals("Should properly convert.", expectedSearchString, actualRaCertificateSearchRequest.getSubjectDnSearchString());
        assertEquals("Should properly convert.", expectedSearchMatchExact, actualRaCertificateSearchRequest.isSubjectDnSearchExact());
        assertEquals("Should properly convert.", expectedSearchString, actualRaCertificateSearchRequest.getSubjectAnSearchString());
        assertEquals("Should properly convert.", expectedSearchMatchExact, actualRaCertificateSearchRequest.isSubjectAnSearchExact());
        assertEquals("Should properly convert.", expectedSearchString, actualRaCertificateSearchRequest.getUsernameSearchString());
        assertEquals("Should properly convert.", expectedSearchMatchExact, actualRaCertificateSearchRequest.isUsernameSearchExact());
        assertEquals("Should properly convert.", "", actualRaCertificateSearchRequest.getSerialNumberSearchStringFromDec());
        assertEquals("Should properly convert.", "", actualRaCertificateSearchRequest.getSerialNumberSearchStringFromHex());
        assertEquals("Should properly convert.", 0L, actualRaCertificateSearchRequest.getIssuedAfter());
        assertEquals("Should properly convert.", Long.MAX_VALUE, actualRaCertificateSearchRequest.getIssuedBefore());
        assertEquals("Should properly convert.", 0L, actualRaCertificateSearchRequest.getExpiresAfter());
        assertEquals("Should properly convert.", Long.MAX_VALUE, actualRaCertificateSearchRequest.getExpiresBefore());
        assertEquals("Should properly convert.", 0L, actualRaCertificateSearchRequest.getRevokedAfter());
        assertEquals("Should properly convert.", Long.MAX_VALUE, actualRaCertificateSearchRequest.getRevokedBefore());
        assertEquals("Should properly convert.", 0, actualRaCertificateSearchRequest.getStatuses().size());
        assertEquals("Should properly convert.", 0, actualRaCertificateSearchRequest.getRevocationReasons().size());
    }

    @Test
    public void shouldProperlyConvertSearchCertificatesRestRequestWithSTATUSPropertyAndEQUALOperationAndValueCERT_ACTIVE() throws RestException {
        // given
        final int expectedPageNumber = 0;
        final int expectedMaxNumberOfResults = 10;
        final String expectedSearchString = CertificateStatus.CERT_ACTIVE.name();
        final Integer expectedCertificateStatus = CertificateStatus.CERT_ACTIVE.getStatusValue();
        final boolean expectedSearchMatchExact = false;
        final SearchCertificateCriteriaRestRequest searchCertificateCriteriaRestRequest = SearchCertificateCriteriaRestRequest.builder()
                .property(CriteriaProperty.STATUS.name())
                .value(expectedSearchString)
                .operation(CriteriaOperation.EQUAL.name())
                .build();
        final SearchCertificatesRestRequest searchCertificatesRestRequest = SearchCertificatesRestRequest.builder()
                .maxNumberOfResults(expectedMaxNumberOfResults)
                .criteria(Collections.singletonList(searchCertificateCriteriaRestRequest))
                .build();
        // when
        final RaCertificateSearchRequest actualRaCertificateSearchRequest = SearchCertificatesRestRequest.converter().toEntity(searchCertificatesRestRequest);
        // then
        assertEquals("Should properly convert.", expectedMaxNumberOfResults, actualRaCertificateSearchRequest.getMaxResults());
        assertEquals("Should properly convert.", expectedPageNumber, actualRaCertificateSearchRequest.getPageNumber());
        assertEquals("Should properly convert.", 0, actualRaCertificateSearchRequest.getEepIds().size());
        assertEquals("Should properly convert.", 0, actualRaCertificateSearchRequest.getCpIds().size());
        assertEquals("Should properly convert.", 0, actualRaCertificateSearchRequest.getCaIds().size());
        assertEquals("Should properly convert.", "", actualRaCertificateSearchRequest.getSubjectDnSearchString());
        assertEquals("Should properly convert.", expectedSearchMatchExact, actualRaCertificateSearchRequest.isSubjectDnSearchExact());
        assertEquals("Should properly convert.", "", actualRaCertificateSearchRequest.getSubjectAnSearchString());
        assertEquals("Should properly convert.", expectedSearchMatchExact, actualRaCertificateSearchRequest.isSubjectAnSearchExact());
        assertEquals("Should properly convert.", "", actualRaCertificateSearchRequest.getUsernameSearchString());
        assertEquals("Should properly convert.", expectedSearchMatchExact, actualRaCertificateSearchRequest.isUsernameSearchExact());
        assertEquals("Should properly convert.", "", actualRaCertificateSearchRequest.getSerialNumberSearchStringFromDec());
        assertEquals("Should properly convert.", "", actualRaCertificateSearchRequest.getSerialNumberSearchStringFromHex());
        assertEquals("Should properly convert.", 0L, actualRaCertificateSearchRequest.getIssuedAfter());
        assertEquals("Should properly convert.", Long.MAX_VALUE, actualRaCertificateSearchRequest.getIssuedBefore());
        assertEquals("Should properly convert.", 0L, actualRaCertificateSearchRequest.getExpiresAfter());
        assertEquals("Should properly convert.", Long.MAX_VALUE, actualRaCertificateSearchRequest.getExpiresBefore());
        assertEquals("Should properly convert.", 0L, actualRaCertificateSearchRequest.getRevokedAfter());
        assertEquals("Should properly convert.", Long.MAX_VALUE, actualRaCertificateSearchRequest.getRevokedBefore());
        assertEquals("Should properly convert.", 1, actualRaCertificateSearchRequest.getStatuses().size());
        assertEquals("Should properly convert.", expectedCertificateStatus, actualRaCertificateSearchRequest.getStatuses().get(0));
        assertEquals("Should properly convert.", 0, actualRaCertificateSearchRequest.getRevocationReasons().size());
    }

    @Test
    public void shouldProperlyConvertSearchCertificatesRestRequestWithSTATUSPropertyAndEQUALOperationAndValueCERT_REVOKED() throws RestException {
        // given
        final int expectedPageNumber = 0;
        final int expectedMaxNumberOfResults = 10;
        final String expectedSearchString = CertificateStatus.CERT_REVOKED.name();
        final Integer expectedCertificateStatus = CertificateStatus.CERT_REVOKED.getStatusValue();
        final boolean expectedSearchMatchExact = false;
        final SearchCertificateCriteriaRestRequest searchCertificateCriteriaRestRequest = SearchCertificateCriteriaRestRequest.builder()
                .property(CriteriaProperty.STATUS.name())
                .value(expectedSearchString)
                .operation(CriteriaOperation.EQUAL.name())
                .build();
        final SearchCertificatesRestRequest searchCertificatesRestRequest = SearchCertificatesRestRequest.builder()
                .maxNumberOfResults(expectedMaxNumberOfResults)
                .criteria(Collections.singletonList(searchCertificateCriteriaRestRequest))
                .build();
        // when
        final RaCertificateSearchRequest actualRaCertificateSearchRequest = SearchCertificatesRestRequest.converter().toEntity(searchCertificatesRestRequest);
        // then
        assertEquals("Should properly convert.", expectedMaxNumberOfResults, actualRaCertificateSearchRequest.getMaxResults());
        assertEquals("Should properly convert.", expectedPageNumber, actualRaCertificateSearchRequest.getPageNumber());
        assertEquals("Should properly convert.", 0, actualRaCertificateSearchRequest.getEepIds().size());
        assertEquals("Should properly convert.", 0, actualRaCertificateSearchRequest.getCpIds().size());
        assertEquals("Should properly convert.", 0, actualRaCertificateSearchRequest.getCaIds().size());
        assertEquals("Should properly convert.", "", actualRaCertificateSearchRequest.getSubjectDnSearchString());
        assertEquals("Should properly convert.", expectedSearchMatchExact, actualRaCertificateSearchRequest.isSubjectDnSearchExact());
        assertEquals("Should properly convert.", "", actualRaCertificateSearchRequest.getSubjectAnSearchString());
        assertEquals("Should properly convert.", expectedSearchMatchExact, actualRaCertificateSearchRequest.isSubjectAnSearchExact());
        assertEquals("Should properly convert.", "", actualRaCertificateSearchRequest.getUsernameSearchString());
        assertEquals("Should properly convert.", expectedSearchMatchExact, actualRaCertificateSearchRequest.isUsernameSearchExact());
        assertEquals("Should properly convert.", "", actualRaCertificateSearchRequest.getSerialNumberSearchStringFromDec());
        assertEquals("Should properly convert.", "", actualRaCertificateSearchRequest.getSerialNumberSearchStringFromHex());
        assertEquals("Should properly convert.", 0L, actualRaCertificateSearchRequest.getIssuedAfter());
        assertEquals("Should properly convert.", Long.MAX_VALUE, actualRaCertificateSearchRequest.getIssuedBefore());
        assertEquals("Should properly convert.", 0L, actualRaCertificateSearchRequest.getExpiresAfter());
        assertEquals("Should properly convert.", Long.MAX_VALUE, actualRaCertificateSearchRequest.getExpiresBefore());
        assertEquals("Should properly convert.", 0L, actualRaCertificateSearchRequest.getRevokedAfter());
        assertEquals("Should properly convert.", Long.MAX_VALUE, actualRaCertificateSearchRequest.getRevokedBefore());
        assertEquals("Should properly convert.", 1, actualRaCertificateSearchRequest.getStatuses().size());
        assertEquals("Should properly convert.", expectedCertificateStatus, actualRaCertificateSearchRequest.getStatuses().get(0));
        assertEquals("Should properly convert.", 0, actualRaCertificateSearchRequest.getRevocationReasons().size());
    }

    @Test
    public void shouldProperlyConvertSearchCertificatesRestRequestWithSTATUSPropertyAndEQUALOperationAndValueREVOCATION_REASON_CACOMPROMISE() throws RestException {
        // given
        final int expectedPageNumber = 0;
        final int expectedMaxNumberOfResults = 10;
        final String expectedSearchString = CertificateStatus.REVOCATION_REASON_CACOMPROMISE.name();
        final Integer expectedRevocationReason = CertificateStatus.REVOCATION_REASON_CACOMPROMISE.getStatusValue();
        final boolean expectedSearchMatchExact = false;
        final SearchCertificateCriteriaRestRequest searchCertificateCriteriaRestRequest = SearchCertificateCriteriaRestRequest.builder()
                .property(CriteriaProperty.STATUS.name())
                .value(expectedSearchString)
                .operation(CriteriaOperation.EQUAL.name())
                .build();
        final SearchCertificatesRestRequest searchCertificatesRestRequest = SearchCertificatesRestRequest.builder()
                .maxNumberOfResults(expectedMaxNumberOfResults)
                .criteria(Collections.singletonList(searchCertificateCriteriaRestRequest))
                .build();
        // when
        final RaCertificateSearchRequest actualRaCertificateSearchRequest = SearchCertificatesRestRequest.converter().toEntity(searchCertificatesRestRequest);
        // then
        assertEquals("Should properly convert.", expectedMaxNumberOfResults, actualRaCertificateSearchRequest.getMaxResults());
        assertEquals("Should properly convert.", expectedPageNumber, actualRaCertificateSearchRequest.getPageNumber());
        assertEquals("Should properly convert.", 0, actualRaCertificateSearchRequest.getEepIds().size());
        assertEquals("Should properly convert.", 0, actualRaCertificateSearchRequest.getCpIds().size());
        assertEquals("Should properly convert.", 0, actualRaCertificateSearchRequest.getCaIds().size());
        assertEquals("Should properly convert.", "", actualRaCertificateSearchRequest.getSubjectDnSearchString());
        assertEquals("Should properly convert.", expectedSearchMatchExact, actualRaCertificateSearchRequest.isSubjectDnSearchExact());
        assertEquals("Should properly convert.", "", actualRaCertificateSearchRequest.getSubjectAnSearchString());
        assertEquals("Should properly convert.", expectedSearchMatchExact, actualRaCertificateSearchRequest.isSubjectAnSearchExact());
        assertEquals("Should properly convert.", "", actualRaCertificateSearchRequest.getUsernameSearchString());
        assertEquals("Should properly convert.", expectedSearchMatchExact, actualRaCertificateSearchRequest.isUsernameSearchExact());
        assertEquals("Should properly convert.", "", actualRaCertificateSearchRequest.getSerialNumberSearchStringFromDec());
        assertEquals("Should properly convert.", "", actualRaCertificateSearchRequest.getSerialNumberSearchStringFromHex());
        assertEquals("Should properly convert.", 0L, actualRaCertificateSearchRequest.getIssuedAfter());
        assertEquals("Should properly convert.", Long.MAX_VALUE, actualRaCertificateSearchRequest.getIssuedBefore());
        assertEquals("Should properly convert.", 0L, actualRaCertificateSearchRequest.getExpiresAfter());
        assertEquals("Should properly convert.", Long.MAX_VALUE, actualRaCertificateSearchRequest.getExpiresBefore());
        assertEquals("Should properly convert.", 0L, actualRaCertificateSearchRequest.getRevokedAfter());
        assertEquals("Should properly convert.", Long.MAX_VALUE, actualRaCertificateSearchRequest.getRevokedBefore());
        assertEquals("Should properly convert.", 0, actualRaCertificateSearchRequest.getStatuses().size());
        assertEquals("Should properly convert.", 1, actualRaCertificateSearchRequest.getRevocationReasons().size());
        assertEquals("Should properly convert.", expectedRevocationReason, actualRaCertificateSearchRequest.getRevocationReasons().get(0));
    }

    @Test
    public void shouldProperlyConvertSearchCertificatesRestRequestWithISSUED_DATEPropertyAndBEFOREOperationAndCorrectValue() throws RestException {
        // given
        final int expectedPageNumber = 0;
        final int expectedMaxNumberOfResults = 10;
        final String expectedSearchString = "2018-06-15T14:07:09Z";
        final Long expectedDateLong = 1529071629000L;
        final boolean expectedSearchMatchExact = false;
        final SearchCertificateCriteriaRestRequest searchCertificateCriteriaRestRequest = SearchCertificateCriteriaRestRequest.builder()
                .property(CriteriaProperty.ISSUED_DATE.name())
                .value(expectedSearchString)
                .operation(CriteriaOperation.BEFORE.name())
                .build();
        final SearchCertificatesRestRequest searchCertificatesRestRequest = SearchCertificatesRestRequest.builder()
                .maxNumberOfResults(expectedMaxNumberOfResults)
                .criteria(Collections.singletonList(searchCertificateCriteriaRestRequest))
                .build();
        // when
        final RaCertificateSearchRequest actualRaCertificateSearchRequest = SearchCertificatesRestRequest.converter().toEntity(searchCertificatesRestRequest);
        // then
        assertEquals("Should properly convert.", expectedMaxNumberOfResults, actualRaCertificateSearchRequest.getMaxResults());
        assertEquals("Should properly convert.", expectedPageNumber, actualRaCertificateSearchRequest.getPageNumber());
        assertEquals("Should properly convert.", 0, actualRaCertificateSearchRequest.getEepIds().size());
        assertEquals("Should properly convert.", 0, actualRaCertificateSearchRequest.getCpIds().size());
        assertEquals("Should properly convert.", 0, actualRaCertificateSearchRequest.getCaIds().size());
        assertEquals("Should properly convert.", "", actualRaCertificateSearchRequest.getSubjectDnSearchString());
        assertEquals("Should properly convert.", expectedSearchMatchExact, actualRaCertificateSearchRequest.isSubjectDnSearchExact());
        assertEquals("Should properly convert.", "", actualRaCertificateSearchRequest.getSubjectAnSearchString());
        assertEquals("Should properly convert.", expectedSearchMatchExact, actualRaCertificateSearchRequest.isSubjectAnSearchExact());
        assertEquals("Should properly convert.", "", actualRaCertificateSearchRequest.getUsernameSearchString());
        assertEquals("Should properly convert.", expectedSearchMatchExact, actualRaCertificateSearchRequest.isUsernameSearchExact());
        assertEquals("Should properly convert.", "", actualRaCertificateSearchRequest.getSerialNumberSearchStringFromDec());
        assertEquals("Should properly convert.", "", actualRaCertificateSearchRequest.getSerialNumberSearchStringFromHex());
        assertEquals("Should properly convert.", 0L, actualRaCertificateSearchRequest.getIssuedAfter());
        assertEquals("Should properly convert.", expectedDateLong, Long.valueOf(actualRaCertificateSearchRequest.getIssuedBefore()));
        assertEquals("Should properly convert.", 0L, actualRaCertificateSearchRequest.getExpiresAfter());
        assertEquals("Should properly convert.", Long.MAX_VALUE, actualRaCertificateSearchRequest.getExpiresBefore());
        assertEquals("Should properly convert.", 0L, actualRaCertificateSearchRequest.getRevokedAfter());
        assertEquals("Should properly convert.", Long.MAX_VALUE, actualRaCertificateSearchRequest.getRevokedBefore());
        assertEquals("Should properly convert.", 0, actualRaCertificateSearchRequest.getStatuses().size());
        assertEquals("Should properly convert.", 0, actualRaCertificateSearchRequest.getRevocationReasons().size());
    }

    @Test
    public void shouldProperlyConvertSearchCertificatesRestRequestWithISSUED_DATEPropertyAndAFTEROperationAndCorrectValue() throws RestException {
        // given
        final int expectedPageNumber = 0;
        final int expectedMaxNumberOfResults = 10;
        final String expectedSearchString = "2018-06-15T14:07:09Z";
        final Long expectedDateLong = 1529071629000L;
        final boolean expectedSearchMatchExact = false;
        final SearchCertificateCriteriaRestRequest searchCertificateCriteriaRestRequest = SearchCertificateCriteriaRestRequest.builder()
                .property(CriteriaProperty.ISSUED_DATE.name())
                .value(expectedSearchString)
                .operation(CriteriaOperation.AFTER.name())
                .build();
        final SearchCertificatesRestRequest searchCertificatesRestRequest = SearchCertificatesRestRequest.builder()
                .maxNumberOfResults(expectedMaxNumberOfResults)
                .criteria(Collections.singletonList(searchCertificateCriteriaRestRequest))
                .build();
        // when
        final RaCertificateSearchRequest actualRaCertificateSearchRequest = SearchCertificatesRestRequest.converter().toEntity(searchCertificatesRestRequest);
        // then
        assertEquals("Should properly convert.", expectedMaxNumberOfResults, actualRaCertificateSearchRequest.getMaxResults());
        assertEquals("Should properly convert.", expectedPageNumber, actualRaCertificateSearchRequest.getPageNumber());
        assertEquals("Should properly convert.", 0, actualRaCertificateSearchRequest.getEepIds().size());
        assertEquals("Should properly convert.", 0, actualRaCertificateSearchRequest.getCpIds().size());
        assertEquals("Should properly convert.", 0, actualRaCertificateSearchRequest.getCaIds().size());
        assertEquals("Should properly convert.", "", actualRaCertificateSearchRequest.getSubjectDnSearchString());
        assertEquals("Should properly convert.", expectedSearchMatchExact, actualRaCertificateSearchRequest.isSubjectDnSearchExact());
        assertEquals("Should properly convert.", "", actualRaCertificateSearchRequest.getSubjectAnSearchString());
        assertEquals("Should properly convert.", expectedSearchMatchExact, actualRaCertificateSearchRequest.isSubjectAnSearchExact());
        assertEquals("Should properly convert.", "", actualRaCertificateSearchRequest.getUsernameSearchString());
        assertEquals("Should properly convert.", expectedSearchMatchExact, actualRaCertificateSearchRequest.isUsernameSearchExact());
        assertEquals("Should properly convert.", "", actualRaCertificateSearchRequest.getSerialNumberSearchStringFromDec());
        assertEquals("Should properly convert.", "", actualRaCertificateSearchRequest.getSerialNumberSearchStringFromHex());
        assertEquals("Should properly convert.", expectedDateLong, Long.valueOf(actualRaCertificateSearchRequest.getIssuedAfter()));
        assertEquals("Should properly convert.", Long.MAX_VALUE, actualRaCertificateSearchRequest.getIssuedBefore());
        assertEquals("Should properly convert.", 0L, actualRaCertificateSearchRequest.getExpiresAfter());
        assertEquals("Should properly convert.", Long.MAX_VALUE, actualRaCertificateSearchRequest.getExpiresBefore());
        assertEquals("Should properly convert.", 0L, actualRaCertificateSearchRequest.getRevokedAfter());
        assertEquals("Should properly convert.", Long.MAX_VALUE, actualRaCertificateSearchRequest.getRevokedBefore());
        assertEquals("Should properly convert.", 0, actualRaCertificateSearchRequest.getStatuses().size());
        assertEquals("Should properly convert.", 0, actualRaCertificateSearchRequest.getRevocationReasons().size());
    }

    @Test(expected = RestException.class)
    public void shouldThrowRestExceptionOnConvertSearchCertificatesRestRequestWithISSUED_DATEPropertyAndBEFOREOperationAndInvalidValue() throws RestException {
        // given
        final String expectedSearchString = "2018";
        final SearchCertificateCriteriaRestRequest searchCertificateCriteriaRestRequest = SearchCertificateCriteriaRestRequest.builder()
                .property(CriteriaProperty.ISSUED_DATE.name())
                .value(expectedSearchString)
                .operation(CriteriaOperation.BEFORE.name())
                .build();
        final SearchCertificatesRestRequest searchCertificatesRestRequest = SearchCertificatesRestRequest.builder()
                .maxNumberOfResults(1)
                .criteria(Collections.singletonList(searchCertificateCriteriaRestRequest))
                .build();
        // when
        SearchCertificatesRestRequest.converter().toEntity(searchCertificatesRestRequest);
    }

    @Test(expected = RestException.class)
    public void shouldThrowRestExceptionOnConvertSearchCertificatesRestRequestWithNullCriterias() throws RestException {
        // given
        final SearchCertificatesRestRequest searchCertificatesRestRequest = SearchCertificatesRestRequest.builder()
                .maxNumberOfResults(1)
                .criteria(null)
                .build();
        // when
        SearchCertificatesRestRequest.converter().toEntity(searchCertificatesRestRequest);
    }

    @Test(expected = RestException.class)
    public void shouldThrowRestExceptionOnConvertSearchCertificatesRestRequestWithEmptyCriterias() throws RestException {
        // given
        final SearchCertificatesRestRequest searchCertificatesRestRequest = SearchCertificatesRestRequest.builder()
                .maxNumberOfResults(1)
                .criteria(Collections.<SearchCertificateCriteriaRestRequest>emptyList())
                .build();
        // when
        SearchCertificatesRestRequest.converter().toEntity(searchCertificatesRestRequest);
    }

    @Test(expected = RestException.class)
    public void shouldThrowRestExceptionOnConvertSearchCertificatesRestRequestWithNullMaxNumberOfResults() throws RestException {
        // given
        final SearchCertificatesRestRequest searchCertificatesRestRequest = SearchCertificatesRestRequest.builder()
                .criteria(Collections.singletonList(SearchCertificateCriteriaRestRequest.builder().build()))
                .build();
        // when
        SearchCertificatesRestRequest.converter().toEntity(searchCertificatesRestRequest);
    }

    @Test(expected = RestException.class)
    public void shouldThrowRestExceptionOnConvertSearchCertificatesRestRequestWithUnknownCriteriaProperty() throws RestException {
        // given
        final SearchCertificatesRestRequest searchCertificatesRestRequest = SearchCertificatesRestRequest.builder()
                .maxNumberOfResults(1)
                .criteria(Collections.singletonList(SearchCertificateCriteriaRestRequest.builder().property("BLAH").build()))
                .build();
        // when
        SearchCertificatesRestRequest.converter().toEntity(searchCertificatesRestRequest);
    }

    @Test(expected = RestException.class)
    public void shouldThrowRestExceptionOnConvertSearchCertificatesRestRequestWithUnknownCertificateStatus() throws RestException {
        // given
        final SearchCertificatesRestRequest searchCertificatesRestRequest = SearchCertificatesRestRequest.builder()
                .maxNumberOfResults(1)
                .criteria(Collections.singletonList(SearchCertificateCriteriaRestRequest.builder().property("STATUS").value("BLAH").build()))
                .build();
        // when
        SearchCertificatesRestRequest.converter().toEntity(searchCertificatesRestRequest);
    }

    @Test
    public void shouldProperlyConvertSearchCertificatesRestRequestWithREVOCATION_DATEPropertyAndBEFOREOperationAndCorrectValue() throws RestException {
        // given
        final int expectedPageNumber = 0;
        final int expectedMaxNumberOfResults = 10;
        final String expectedSearchString = "2018-06-15T14:07:09Z";
        final Long expectedDateLong = 1529071629000L;
        final boolean expectedSearchMatchExact = false;
        final SearchCertificateCriteriaRestRequest searchCertificateCriteriaRestRequest = SearchCertificateCriteriaRestRequest.builder()
                .property(CriteriaProperty.REVOCATION_DATE.name())
                .value(expectedSearchString)
                .operation(CriteriaOperation.BEFORE.name())
                .build();
        final SearchCertificatesRestRequest searchCertificatesRestRequest = SearchCertificatesRestRequest.builder()
                .maxNumberOfResults(expectedMaxNumberOfResults)
                .criteria(Collections.singletonList(searchCertificateCriteriaRestRequest))
                .build();
        // when
        final RaCertificateSearchRequest actualRaCertificateSearchRequest = SearchCertificatesRestRequest.converter().toEntity(searchCertificatesRestRequest);
        // then
        assertEquals("Should properly convert.", expectedMaxNumberOfResults, actualRaCertificateSearchRequest.getMaxResults());
        assertEquals("Should properly convert.", expectedPageNumber, actualRaCertificateSearchRequest.getPageNumber());
        assertEquals("Should properly convert.", 0, actualRaCertificateSearchRequest.getEepIds().size());
        assertEquals("Should properly convert.", 0, actualRaCertificateSearchRequest.getCpIds().size());
        assertEquals("Should properly convert.", 0, actualRaCertificateSearchRequest.getCaIds().size());
        assertEquals("Should properly convert.", "", actualRaCertificateSearchRequest.getSubjectDnSearchString());
        assertEquals("Should properly convert.", expectedSearchMatchExact, actualRaCertificateSearchRequest.isSubjectDnSearchExact());
        assertEquals("Should properly convert.", "", actualRaCertificateSearchRequest.getSubjectAnSearchString());
        assertEquals("Should properly convert.", expectedSearchMatchExact, actualRaCertificateSearchRequest.isSubjectAnSearchExact());
        assertEquals("Should properly convert.", "", actualRaCertificateSearchRequest.getUsernameSearchString());
        assertEquals("Should properly convert.", expectedSearchMatchExact, actualRaCertificateSearchRequest.isUsernameSearchExact());
        assertEquals("Should properly convert.", "", actualRaCertificateSearchRequest.getSerialNumberSearchStringFromDec());
        assertEquals("Should properly convert.", "", actualRaCertificateSearchRequest.getSerialNumberSearchStringFromHex());
        assertEquals("Should properly convert.", 0L, actualRaCertificateSearchRequest.getIssuedAfter());
        assertEquals("Should properly convert.", Long.MAX_VALUE, actualRaCertificateSearchRequest.getIssuedBefore());
        assertEquals("Should properly convert.", 0L, actualRaCertificateSearchRequest.getExpiresAfter());
        assertEquals("Should properly convert.", Long.MAX_VALUE, actualRaCertificateSearchRequest.getExpiresBefore());
        assertEquals("Should properly convert.", 0L, actualRaCertificateSearchRequest.getRevokedAfter());
        assertEquals("Should properly convert.", expectedDateLong, Long.valueOf(actualRaCertificateSearchRequest.getRevokedBefore()));
        assertEquals("Should properly convert.", 0, actualRaCertificateSearchRequest.getStatuses().size());
        assertEquals("Should properly convert.", 0, actualRaCertificateSearchRequest.getRevocationReasons().size());
    }

    @Test
    public void shouldProperlyConvertSearchCertificatesRestRequestWithREVOCATION_DATEPropertyAndAFTEROperationAndCorrectValue() throws RestException {
        // given
        final int expectedPageNumber = 0;
        final int expectedMaxNumberOfResults = 10;
        final String expectedSearchString = "2018-06-15T14:07:09Z";
        final Long expectedDateLong = 1529071629000L;
        final boolean expectedSearchMatchExact = false;
        final SearchCertificateCriteriaRestRequest searchCertificateCriteriaRestRequest = SearchCertificateCriteriaRestRequest.builder()
                .property(CriteriaProperty.REVOCATION_DATE.name())
                .value(expectedSearchString)
                .operation(CriteriaOperation.AFTER.name())
                .build();
        final SearchCertificatesRestRequest searchCertificatesRestRequest = SearchCertificatesRestRequest.builder()
                .maxNumberOfResults(expectedMaxNumberOfResults)
                .criteria(Collections.singletonList(searchCertificateCriteriaRestRequest))
                .build();
        // when
        final RaCertificateSearchRequest actualRaCertificateSearchRequest = SearchCertificatesRestRequest.converter().toEntity(searchCertificatesRestRequest);
        // then
        assertEquals("Should properly convert.", expectedMaxNumberOfResults, actualRaCertificateSearchRequest.getMaxResults());
        assertEquals("Should properly convert.", expectedPageNumber, actualRaCertificateSearchRequest.getPageNumber());
        assertEquals("Should properly convert.", 0, actualRaCertificateSearchRequest.getEepIds().size());
        assertEquals("Should properly convert.", 0, actualRaCertificateSearchRequest.getCpIds().size());
        assertEquals("Should properly convert.", 0, actualRaCertificateSearchRequest.getCaIds().size());
        assertEquals("Should properly convert.", "", actualRaCertificateSearchRequest.getSubjectDnSearchString());
        assertEquals("Should properly convert.", expectedSearchMatchExact, actualRaCertificateSearchRequest.isSubjectDnSearchExact());
        assertEquals("Should properly convert.", "", actualRaCertificateSearchRequest.getSubjectAnSearchString());
        assertEquals("Should properly convert.", expectedSearchMatchExact, actualRaCertificateSearchRequest.isSubjectAnSearchExact());
        assertEquals("Should properly convert.", "", actualRaCertificateSearchRequest.getUsernameSearchString());
        assertEquals("Should properly convert.", expectedSearchMatchExact, actualRaCertificateSearchRequest.isUsernameSearchExact());
        assertEquals("Should properly convert.", "", actualRaCertificateSearchRequest.getSerialNumberSearchStringFromDec());
        assertEquals("Should properly convert.", "", actualRaCertificateSearchRequest.getSerialNumberSearchStringFromHex());
        assertEquals("Should properly convert.", 0L, actualRaCertificateSearchRequest.getIssuedAfter());
        assertEquals("Should properly convert.", Long.MAX_VALUE, actualRaCertificateSearchRequest.getIssuedBefore());
        assertEquals("Should properly convert.", 0L, actualRaCertificateSearchRequest.getExpiresAfter());
        assertEquals("Should properly convert.", Long.MAX_VALUE, actualRaCertificateSearchRequest.getExpiresBefore());
        assertEquals("Should properly convert.", expectedDateLong, Long.valueOf(actualRaCertificateSearchRequest.getRevokedAfter()));
        assertEquals("Should properly convert.", Long.MAX_VALUE, actualRaCertificateSearchRequest.getRevokedBefore());
        assertEquals("Should properly convert.", 0, actualRaCertificateSearchRequest.getStatuses().size());
        assertEquals("Should properly convert.", 0, actualRaCertificateSearchRequest.getRevocationReasons().size());
    }

    @Test
    public void shouldProperlyConvertSearchCertificatesRestRequestWithEXPIRE_DATEPropertyAndBEFOREOperationAndCorrectValue() throws RestException {
        // given
        final int expectedPageNumber = 0;
        final int expectedMaxNumberOfResults = 10;
        final String expectedSearchString = "2018-06-15T14:07:09Z";
        final Long expectedDateLong = 1529071629000L;
        final boolean expectedSearchMatchExact = false;
        final SearchCertificateCriteriaRestRequest searchCertificateCriteriaRestRequest = SearchCertificateCriteriaRestRequest.builder()
                .property(CriteriaProperty.EXPIRE_DATE.name())
                .value(expectedSearchString)
                .operation(CriteriaOperation.BEFORE.name())
                .build();
        final SearchCertificatesRestRequest searchCertificatesRestRequest = SearchCertificatesRestRequest.builder()
                .maxNumberOfResults(expectedMaxNumberOfResults)
                .criteria(Collections.singletonList(searchCertificateCriteriaRestRequest))
                .build();
        // when
        final RaCertificateSearchRequest actualRaCertificateSearchRequest = SearchCertificatesRestRequest.converter().toEntity(searchCertificatesRestRequest);
        // then
        assertEquals("Should properly convert.", expectedMaxNumberOfResults, actualRaCertificateSearchRequest.getMaxResults());
        assertEquals("Should properly convert.", expectedPageNumber, actualRaCertificateSearchRequest.getPageNumber());
        assertEquals("Should properly convert.", 0, actualRaCertificateSearchRequest.getEepIds().size());
        assertEquals("Should properly convert.", 0, actualRaCertificateSearchRequest.getCpIds().size());
        assertEquals("Should properly convert.", 0, actualRaCertificateSearchRequest.getCaIds().size());
        assertEquals("Should properly convert.", "", actualRaCertificateSearchRequest.getSubjectDnSearchString());
        assertEquals("Should properly convert.", expectedSearchMatchExact, actualRaCertificateSearchRequest.isSubjectDnSearchExact());
        assertEquals("Should properly convert.", "", actualRaCertificateSearchRequest.getSubjectAnSearchString());
        assertEquals("Should properly convert.", expectedSearchMatchExact, actualRaCertificateSearchRequest.isSubjectAnSearchExact());
        assertEquals("Should properly convert.", "", actualRaCertificateSearchRequest.getUsernameSearchString());
        assertEquals("Should properly convert.", expectedSearchMatchExact, actualRaCertificateSearchRequest.isUsernameSearchExact());
        assertEquals("Should properly convert.", "", actualRaCertificateSearchRequest.getSerialNumberSearchStringFromDec());
        assertEquals("Should properly convert.", "", actualRaCertificateSearchRequest.getSerialNumberSearchStringFromHex());
        assertEquals("Should properly convert.", 0L, actualRaCertificateSearchRequest.getIssuedAfter());
        assertEquals("Should properly convert.", Long.MAX_VALUE, actualRaCertificateSearchRequest.getIssuedBefore());
        assertEquals("Should properly convert.", 0L, actualRaCertificateSearchRequest.getExpiresAfter());
        assertEquals("Should properly convert.", expectedDateLong, Long.valueOf(actualRaCertificateSearchRequest.getExpiresBefore()));
        assertEquals("Should properly convert.", 0L, actualRaCertificateSearchRequest.getRevokedAfter());
        assertEquals("Should properly convert.", Long.MAX_VALUE, actualRaCertificateSearchRequest.getRevokedBefore());
        assertEquals("Should properly convert.", 0, actualRaCertificateSearchRequest.getStatuses().size());
        assertEquals("Should properly convert.", 0, actualRaCertificateSearchRequest.getRevocationReasons().size());
    }

    @Test
    public void shouldProperlyConvertSearchCertificatesRestRequestWithEXPIRE_DATEPropertyAndAFTEROperationAndCorrectValue() throws RestException {
        // given
        final int expectedPageNumber = 0;
        final int expectedMaxNumberOfResults = 10;
        final String expectedSearchString = "2018-06-15T14:07:09Z";
        final Long expectedDateLong = 1529071629000L;
        final boolean expectedSearchMatchExact = false;
        final SearchCertificateCriteriaRestRequest searchCertificateCriteriaRestRequest = SearchCertificateCriteriaRestRequest.builder()
                .property(CriteriaProperty.EXPIRE_DATE.name())
                .value(expectedSearchString)
                .operation(CriteriaOperation.AFTER.name())
                .build();
        final SearchCertificatesRestRequest searchCertificatesRestRequest = SearchCertificatesRestRequest.builder()
                .maxNumberOfResults(expectedMaxNumberOfResults)
                .criteria(Collections.singletonList(searchCertificateCriteriaRestRequest))
                .build();
        // when
        final RaCertificateSearchRequest actualRaCertificateSearchRequest = SearchCertificatesRestRequest.converter().toEntity(searchCertificatesRestRequest);
        // then
        assertEquals("Should properly convert.", expectedMaxNumberOfResults, actualRaCertificateSearchRequest.getMaxResults());
        assertEquals("Should properly convert.", expectedPageNumber, actualRaCertificateSearchRequest.getPageNumber());
        assertEquals("Should properly convert.", 0, actualRaCertificateSearchRequest.getEepIds().size());
        assertEquals("Should properly convert.", 0, actualRaCertificateSearchRequest.getCpIds().size());
        assertEquals("Should properly convert.", 0, actualRaCertificateSearchRequest.getCaIds().size());
        assertEquals("Should properly convert.", "", actualRaCertificateSearchRequest.getSubjectDnSearchString());
        assertEquals("Should properly convert.", expectedSearchMatchExact, actualRaCertificateSearchRequest.isSubjectDnSearchExact());
        assertEquals("Should properly convert.", "", actualRaCertificateSearchRequest.getSubjectAnSearchString());
        assertEquals("Should properly convert.", expectedSearchMatchExact, actualRaCertificateSearchRequest.isSubjectAnSearchExact());
        assertEquals("Should properly convert.", "", actualRaCertificateSearchRequest.getUsernameSearchString());
        assertEquals("Should properly convert.", expectedSearchMatchExact, actualRaCertificateSearchRequest.isUsernameSearchExact());
        assertEquals("Should properly convert.", "", actualRaCertificateSearchRequest.getSerialNumberSearchStringFromDec());
        assertEquals("Should properly convert.", "", actualRaCertificateSearchRequest.getSerialNumberSearchStringFromHex());
        assertEquals("Should properly convert.", 0L, actualRaCertificateSearchRequest.getIssuedAfter());
        assertEquals("Should properly convert.", Long.MAX_VALUE, actualRaCertificateSearchRequest.getIssuedBefore());
        assertEquals("Should properly convert.", expectedDateLong, Long.valueOf(actualRaCertificateSearchRequest.getExpiresAfter()));
        assertEquals("Should properly convert.", Long.MAX_VALUE, actualRaCertificateSearchRequest.getExpiresBefore());
        assertEquals("Should properly convert.", 0L, actualRaCertificateSearchRequest.getRevokedAfter());
        assertEquals("Should properly convert.", Long.MAX_VALUE, actualRaCertificateSearchRequest.getRevokedBefore());
        assertEquals("Should properly convert.", 0, actualRaCertificateSearchRequest.getStatuses().size());
        assertEquals("Should properly convert.", 0, actualRaCertificateSearchRequest.getRevocationReasons().size());
    }
}

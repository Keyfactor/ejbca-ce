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
package org.ejbca.ui.web.rest.api.validator;

import org.apache.log4j.Logger;
import org.easymock.EasyMock;
import org.ejbca.ui.web.rest.api.io.request.SearchCertificateCriteriaRestRequest;
import org.ejbca.ui.web.rest.api.io.request.SearchCertificatesRestRequest;
import org.ejbca.ui.web.rest.api.resource.builder.SearchCertificatesRestRequestTestBuilder;
import org.junit.Before;
import org.junit.Test;

import jakarta.validation.ConstraintValidatorContext;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.easymock.EasyMock.createMock;
import static org.easymock.EasyMock.createNiceMock;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * A unit test class for annotation @ValidSearchCertificateCriteriaRestRequestList and its validator.
 * <br/>
 * <b>Note: </b> Due to test compilation issue ECA-7148, we use an original input class SearchCertificatesRestRequest instead of simplified annotated class.
 *
 */
public class ValidSearchCertificateCriteriaRestRequestListUnitTest {

    private static Logger log = Logger.getLogger(ValidSearchCertificateCriteriaRestRequestListUnitTest.class);
    private ConstraintValidatorContext constraintValidatorContextMock;
    private ConstraintValidatorContext.ConstraintViolationBuilder constraintViolationBuilderMock;
    ValidSearchCertificateCriteriaRestRequestList.Validator validator;

    @Before
    public void setUp() throws Exception {

        constraintValidatorContextMock = createNiceMock(ConstraintValidatorContext.class);
        constraintViolationBuilderMock = createMock(ConstraintValidatorContext.ConstraintViolationBuilder.class);

        replay();
        validator = new ValidSearchCertificateCriteriaRestRequestList.Validator();
    }

    @Test
    public void validationShouldFailOnNullValue() {
        // given
        final String expectedMessage = "{ValidSearchCertificateCriteriaRestRequestList.invalid.null}";
        EasyMock.expect(constraintValidatorContextMock.buildConstraintViolationWithTemplate(expectedMessage)).andReturn(constraintViolationBuilderMock).once();
        replay(constraintValidatorContextMock);
        List<SearchCertificateCriteriaRestRequest> searchCertificateCriteriaRestRequests = null;
        // when
        boolean valid = validator.isValid(searchCertificateCriteriaRestRequests, constraintValidatorContextMock);
        // then
        assertFalse("Invalid object.", valid);
        verify(constraintValidatorContextMock);
    }

    @Test
    public void validationShouldFailOnEmptyValue() {
        // given
        final String expectedMessage = "{ValidSearchCertificateCriteriaRestRequestList.invalid.empty}";
        EasyMock.expect(constraintValidatorContextMock.buildConstraintViolationWithTemplate(expectedMessage)).andReturn(constraintViolationBuilderMock).once();
        replay(constraintValidatorContextMock);
        List<SearchCertificateCriteriaRestRequest> searchCertificateCriteriaRestRequests = new ArrayList<SearchCertificateCriteriaRestRequest>();
        // when
        boolean valid = validator.isValid(searchCertificateCriteriaRestRequests, constraintValidatorContextMock);
        // then
        assertFalse("Invalid object.", valid);
        verify(constraintValidatorContextMock);
    }

    @Test
    public void validationShouldPassOnNormalValue() {
        // given
        final SearchCertificatesRestRequest testRequest = SearchCertificatesRestRequestTestBuilder.withDefaults().build();
        // when
        boolean valid = validator.isValid(testRequest.getCriteria(), constraintValidatorContextMock);
        // then
        assertTrue("Valid object.", valid);
    }

    @Test
    public void validationShouldFailOn2QueryCriteria() {
        // given
        final String expectedMessage = "{ValidSearchCertificateCriteriaRestRequestList.invalid.multipleQueries}";
        EasyMock.expect(constraintValidatorContextMock.buildConstraintViolationWithTemplate(expectedMessage)).andReturn(constraintViolationBuilderMock).once();
        replay(constraintValidatorContextMock);
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest0 = SearchCertificateCriteriaRestRequest.builder().property("QUERY").value("TEST").operation("EQUAL").build();
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest1 = SearchCertificateCriteriaRestRequest.builder().property("QUERY").value("TEST").operation("EQUAL").build();
        final SearchCertificatesRestRequest testRequest = SearchCertificatesRestRequestTestBuilder.withDefaults()
                .criteria(Arrays.asList(querySearchCertificateCriteriaRestRequest0, querySearchCertificateCriteriaRestRequest1))
                .build();
        // when
        boolean valid = validator.isValid(testRequest.getCriteria(), constraintValidatorContextMock);
        // then
        assertFalse("Only one query allowed at a time.", valid);
        verify(constraintValidatorContextMock);
    }

    @Test
    public void validationShouldFailOn2StringValueCriteria() {
        // given
        final String expectedMessage = "{ValidSearchCertificateCriteriaRestRequestList.invalid.multipleStringCriteria}";
        EasyMock.expect(constraintValidatorContextMock.buildConstraintViolationWithTemplate(expectedMessage)).andReturn(constraintViolationBuilderMock).once();
        replay(constraintValidatorContextMock);
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest0 = SearchCertificateCriteriaRestRequest.builder().property("USERNAME").value("TEST").operation("EQUAL").build();
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest1 = SearchCertificateCriteriaRestRequest.builder().property("SUBJECT_DN").value("TEST").operation("EQUAL").build();
        final SearchCertificatesRestRequest testRequest = SearchCertificatesRestRequestTestBuilder.withDefaults()
                .criteria(Arrays.asList(querySearchCertificateCriteriaRestRequest0, querySearchCertificateCriteriaRestRequest1))
                .build();
        // when
        boolean valid = validator.isValid(testRequest.getCriteria(), constraintValidatorContextMock);
        // then
        assertFalse("Only one query allowed at a time.", valid);
        verify(constraintValidatorContextMock);
    }

    @Test
    public void validationShouldFailOn13StatusCriteria() {
        // given
        final String expectedMessage = "{ValidSearchCertificateCriteriaRestRequestList.invalid.statusRepetition}";
        EasyMock.expect(constraintValidatorContextMock.buildConstraintViolationWithTemplate(expectedMessage)).andReturn(constraintViolationBuilderMock).once();
        replay(constraintValidatorContextMock);
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest0 = SearchCertificateCriteriaRestRequest.builder().property("STATUS").value("CERT_ACTIVE").operation("EQUAL").build();
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest1 = SearchCertificateCriteriaRestRequest.builder().property("STATUS").value("CERT_ACTIVE").operation("EQUAL").build();
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest2 = SearchCertificateCriteriaRestRequest.builder().property("STATUS").value("CERT_ACTIVE").operation("EQUAL").build();
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest3 = SearchCertificateCriteriaRestRequest.builder().property("STATUS").value("CERT_ACTIVE").operation("EQUAL").build();
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest4 = SearchCertificateCriteriaRestRequest.builder().property("STATUS").value("CERT_ACTIVE").operation("EQUAL").build();
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest5 = SearchCertificateCriteriaRestRequest.builder().property("STATUS").value("CERT_ACTIVE").operation("EQUAL").build();
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest6 = SearchCertificateCriteriaRestRequest.builder().property("STATUS").value("CERT_ACTIVE").operation("EQUAL").build();
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest7 = SearchCertificateCriteriaRestRequest.builder().property("STATUS").value("CERT_ACTIVE").operation("EQUAL").build();
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest8 = SearchCertificateCriteriaRestRequest.builder().property("STATUS").value("CERT_ACTIVE").operation("EQUAL").build();
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest9 = SearchCertificateCriteriaRestRequest.builder().property("STATUS").value("CERT_ACTIVE").operation("EQUAL").build();
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest10 = SearchCertificateCriteriaRestRequest.builder().property("STATUS").value("CERT_ACTIVE").operation("EQUAL").build();
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest11 = SearchCertificateCriteriaRestRequest.builder().property("STATUS").value("CERT_ACTIVE").operation("EQUAL").build();
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest12 = SearchCertificateCriteriaRestRequest.builder().property("STATUS").value("CERT_ACTIVE").operation("EQUAL").build();
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest13 = SearchCertificateCriteriaRestRequest.builder().property("STATUS").value("CERT_ACTIVE").operation("EQUAL").build();
        final SearchCertificatesRestRequest testRequest = SearchCertificatesRestRequestTestBuilder.withDefaults()
                .criteria(
                        Arrays.asList(
                                querySearchCertificateCriteriaRestRequest0, querySearchCertificateCriteriaRestRequest1, querySearchCertificateCriteriaRestRequest2,
                                querySearchCertificateCriteriaRestRequest3, querySearchCertificateCriteriaRestRequest4, querySearchCertificateCriteriaRestRequest5,
                                querySearchCertificateCriteriaRestRequest6, querySearchCertificateCriteriaRestRequest7, querySearchCertificateCriteriaRestRequest8,
                                querySearchCertificateCriteriaRestRequest9, querySearchCertificateCriteriaRestRequest10, querySearchCertificateCriteriaRestRequest11,
                                querySearchCertificateCriteriaRestRequest12, querySearchCertificateCriteriaRestRequest13
                        )
                )
                .build();

        // when
        boolean valid = validator.isValid(testRequest.getCriteria(), constraintValidatorContextMock);
        // then
        assertFalse("Up to 12 are allowed.", valid);
        verify(constraintValidatorContextMock);
    }

    @Test
    public void validationShouldFailOn2ISSUED_DATEBeforeCriteria() {
        // given
        final String expectedMessage = "{ValidSearchCertificateCriteriaRestRequestList.invalid.multipleIssuedDateBefore}";
        EasyMock.expect(constraintValidatorContextMock.buildConstraintViolationWithTemplate(expectedMessage)).andReturn(constraintViolationBuilderMock).once();
        replay(constraintValidatorContextMock);
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest0 = SearchCertificateCriteriaRestRequest.builder().property("ISSUED_DATE").operation("BEFORE").value("2018-06-15T14:07:09Z").build();
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest1 = SearchCertificateCriteriaRestRequest.builder().property("ISSUED_DATE").operation("BEFORE").value("2018-06-15T14:07:09Z").build();
        final SearchCertificatesRestRequest testRequest = SearchCertificatesRestRequestTestBuilder.withDefaults()
                .criteria(Arrays.asList(querySearchCertificateCriteriaRestRequest0, querySearchCertificateCriteriaRestRequest1))
                .build();
        // when
        boolean valid = validator.isValid(testRequest.getCriteria(), constraintValidatorContextMock);
        // then
        assertFalse("Only one 'BEFORE' 'ISSUED_DATE' is allowed at a time.", valid);
        verify(constraintValidatorContextMock);
    }

    @Test
    public void validationShouldFailOn2ISSUED_DATEAfterCriteria() {
        // given
        final String expectedMessage = "{ValidSearchCertificateCriteriaRestRequestList.invalid.multipleIssuedDateAfter}";
        EasyMock.expect(constraintValidatorContextMock.buildConstraintViolationWithTemplate(expectedMessage)).andReturn(constraintViolationBuilderMock).once();
        replay(constraintValidatorContextMock);
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest0 = SearchCertificateCriteriaRestRequest.builder().property("ISSUED_DATE").operation("AFTER").value("2018-06-15T14:07:09Z").build();
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest1 = SearchCertificateCriteriaRestRequest.builder().property("ISSUED_DATE").operation("AFTER").value("2018-06-15T14:07:09Z").build();
        final SearchCertificatesRestRequest testRequest = SearchCertificatesRestRequestTestBuilder.withDefaults()
                .criteria(Arrays.asList(querySearchCertificateCriteriaRestRequest0, querySearchCertificateCriteriaRestRequest1))
                .build();

        // when
        boolean valid = validator.isValid(testRequest.getCriteria(), constraintValidatorContextMock);
        // then
        assertFalse("Only one 'AFTER' 'ISSUED_DATE' is allowed at a time.", valid);
        verify(constraintValidatorContextMock);
    }

    @Test
    public void validationShouldFailOn2EXPIRE_DATEBeforeCriteria() {
        // given
        final String expectedMessage = "{ValidSearchCertificateCriteriaRestRequestList.invalid.multipleExpireDateBefore}";
        EasyMock.expect(constraintValidatorContextMock.buildConstraintViolationWithTemplate(expectedMessage)).andReturn(constraintViolationBuilderMock).once();
        replay(constraintValidatorContextMock);
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest0 = SearchCertificateCriteriaRestRequest.builder().property("EXPIRE_DATE").operation("BEFORE").value("2018-06-15T14:07:09Z").build();
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest1 = SearchCertificateCriteriaRestRequest.builder().property("EXPIRE_DATE").operation("BEFORE").value("2018-06-15T14:07:09Z").build();
        final SearchCertificatesRestRequest testRequest = SearchCertificatesRestRequestTestBuilder.withDefaults()
                .criteria(Arrays.asList(querySearchCertificateCriteriaRestRequest0, querySearchCertificateCriteriaRestRequest1))
                .build();
        // when
        boolean valid = validator.isValid(testRequest.getCriteria(), constraintValidatorContextMock);
        // then
        assertFalse("Only one 'BEFORE' 'EXPIRE_DATE' is allowed at a time.", valid);
        verify(constraintValidatorContextMock);
    }

    @Test
    public void validationShouldFailOn2EXPIRE_DATEAfterCriteria() {
        // given
        final String expectedMessage = "{ValidSearchCertificateCriteriaRestRequestList.invalid.multipleExpireDateAfter}";
        EasyMock.expect(constraintValidatorContextMock.buildConstraintViolationWithTemplate(expectedMessage)).andReturn(constraintViolationBuilderMock).once();
        replay(constraintValidatorContextMock);
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest0 = SearchCertificateCriteriaRestRequest.builder().property("EXPIRE_DATE").operation("AFTER").value("2018-06-15T14:07:09Z").build();
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest1 = SearchCertificateCriteriaRestRequest.builder().property("EXPIRE_DATE").operation("AFTER").value("2018-06-15T14:07:09Z").build();
        final SearchCertificatesRestRequest testRequest = SearchCertificatesRestRequestTestBuilder.withDefaults()
                .criteria(Arrays.asList(querySearchCertificateCriteriaRestRequest0, querySearchCertificateCriteriaRestRequest1))
                .build();
        // when
        boolean valid = validator.isValid(testRequest.getCriteria(), constraintValidatorContextMock);
        // then
        assertFalse("Only one 'AFTER' 'EXPIRE_DATE' is allowed at a time.", valid);
        verify(constraintValidatorContextMock);
    }

    @Test
    public void validationShouldFailOn2REVOCATION_DATEBeforeCriteria() {
        // given
        final String expectedMessage = "{ValidSearchCertificateCriteriaRestRequestList.invalid.multipleRevocationDateBefore}";
        EasyMock.expect(constraintValidatorContextMock.buildConstraintViolationWithTemplate(expectedMessage)).andReturn(constraintViolationBuilderMock).once();
        replay(constraintValidatorContextMock);
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest0 = SearchCertificateCriteriaRestRequest.builder().property("REVOCATION_DATE").operation("BEFORE").value("2018-06-15T14:07:09Z").build();
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest1 = SearchCertificateCriteriaRestRequest.builder().property("REVOCATION_DATE").operation("BEFORE").value("2018-06-15T14:07:09Z").build();
        final SearchCertificatesRestRequest testRequest = SearchCertificatesRestRequestTestBuilder.withDefaults()
                .criteria(Arrays.asList(querySearchCertificateCriteriaRestRequest0, querySearchCertificateCriteriaRestRequest1))
                .build();
        // when
        boolean valid = validator.isValid(testRequest.getCriteria(), constraintValidatorContextMock);
        // then
        assertFalse("Only one 'BEFORE' 'REVOCATION_DATE' is allowed at a time.", valid);
        verify(constraintValidatorContextMock);
    }

    @Test
    public void validationShouldFailOn2REVOCATION_DATEAfterCriteria() {
        // given
        final String expectedMessage = "{ValidSearchCertificateCriteriaRestRequestList.invalid.multipleRevocationDateAfter}";
        EasyMock.expect(constraintValidatorContextMock.buildConstraintViolationWithTemplate(expectedMessage)).andReturn(constraintViolationBuilderMock).once();
        replay(constraintValidatorContextMock);
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest0 = SearchCertificateCriteriaRestRequest.builder().property("REVOCATION_DATE").operation("AFTER").value("2018-06-15T14:07:09Z").build();
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest1 = SearchCertificateCriteriaRestRequest.builder().property("REVOCATION_DATE").operation("AFTER").value("2018-06-15T14:07:09Z").build();
        final SearchCertificatesRestRequest testRequest = SearchCertificatesRestRequestTestBuilder.withDefaults()
                .criteria(Arrays.asList(querySearchCertificateCriteriaRestRequest0, querySearchCertificateCriteriaRestRequest1))
                .build();
        // when
        boolean valid = validator.isValid(testRequest.getCriteria(), constraintValidatorContextMock);
        // then
        assertFalse("Only one 'AFTER' 'REVOCATION_DATE' is allowed at a time.", valid);
        verify(constraintValidatorContextMock);
    }
}

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

import jakarta.validation.ConstraintValidatorContext;
import org.easymock.EasyMock;
import org.ejbca.ui.web.rest.api.io.request.SearchApprovalRestRequest;
import org.junit.Test;

import static org.junit.Assert.assertFalse;

/**
 * A unit test class for annotation @ValidSearchApprovalRestRequest and its validator.
 */
public class ValidSearchApprovalRestRequestUnitTest {

    private ConstraintValidatorContext createConstraintValidatorContextMock() {
        final ConstraintValidatorContext context = EasyMock.createNiceMock(ConstraintValidatorContext.class);
        final ConstraintValidatorContext.ConstraintViolationBuilder violationBuilder =
                EasyMock.createNiceMock(ConstraintValidatorContext.ConstraintViolationBuilder.class);
        final ConstraintValidatorContext.ConstraintViolationBuilder.NodeBuilderCustomizableContext nodeBuilder =
                EasyMock.createNiceMock(ConstraintValidatorContext.ConstraintViolationBuilder.NodeBuilderCustomizableContext.class);

        context.disableDefaultConstraintViolation();
        EasyMock.expectLastCall().anyTimes();

        EasyMock.expect(context.buildConstraintViolationWithTemplate(EasyMock.anyString()))
                .andReturn(violationBuilder).anyTimes();

        EasyMock.expect(violationBuilder.addConstraintViolation())
                .andReturn(context).anyTimes();

        EasyMock.expect(violationBuilder.addPropertyNode(EasyMock.anyString()))
                .andReturn(nodeBuilder).anyTimes();

        EasyMock.expect(nodeBuilder.addConstraintViolation())
                .andReturn(context).anyTimes();

        EasyMock.replay(context, violationBuilder, nodeBuilder);
        return context;
    }

    @Test
    public void testNullRequest() {
        final ConstraintValidatorContext context = createConstraintValidatorContextMock();

        ValidSearchApprovalRestRequest.Validator validator = new ValidSearchApprovalRestRequest.Validator();
        boolean result = validator.isValid(null, context);

        assertFalse("The request should be invalid when it is null.", result);
    }

    @Test
    public void testInvalidDates() {
        SearchApprovalRestRequest request = new SearchApprovalRestRequest();
        final ConstraintValidatorContext context = createConstraintValidatorContextMock();

        request.setCreatedOnOrAfter("Invalid Date");
        request.setCreatedOnOrBefore("Invalid Date");

        ValidSearchApprovalRestRequest.Validator validator = new ValidSearchApprovalRestRequest.Validator();
        boolean result = validator.isValid(request, context);

        assertFalse("The request should be invalid when createdOnOrAfter is after createdOnOrBefore.", result);
    }

    @Test
    public void testInvalidEmail() {
        SearchApprovalRestRequest request = new SearchApprovalRestRequest();
        final ConstraintValidatorContext context = createConstraintValidatorContextMock();

        request.setEmail("invalid email");

        ValidSearchApprovalRestRequest.Validator validator = new ValidSearchApprovalRestRequest.Validator();
        boolean result = validator.isValid(request, context);

        assertFalse("The request should be invalid when the email format is incorrect.", result);
    }

    @Test
    public void testNegativeDaysRequestExpire() {
        SearchApprovalRestRequest request = new SearchApprovalRestRequest();
        final ConstraintValidatorContext context = createConstraintValidatorContextMock();

        request.setDaysRequestsExpireIn("-1");

        ValidSearchApprovalRestRequest.Validator validator = new ValidSearchApprovalRestRequest.Validator();
        boolean result = validator.isValid(request, context);

        assertFalse("The request should be invalid when daysRequestsExpireIn is negative.", result);
    }

    @Test
    public void testInvalidDaysRequestExpireValue() {
        SearchApprovalRestRequest request = new SearchApprovalRestRequest();
        final ConstraintValidatorContext context = createConstraintValidatorContextMock();

        request.setDaysRequestsExpireIn("1blabla");

        ValidSearchApprovalRestRequest.Validator validator = new ValidSearchApprovalRestRequest.Validator();
        boolean result = validator.isValid(request, context);

        assertFalse("The request should be invalid when daysRequestsExpireIn is invalid string.", result);
    }

    @Test
    public void testMissingCriteria() {
        SearchApprovalRestRequest request = new SearchApprovalRestRequest();
        final ConstraintValidatorContext context = createConstraintValidatorContextMock();

        ValidSearchApprovalRestRequest.Validator validator = new ValidSearchApprovalRestRequest.Validator();
        boolean result = validator.isValid(request, context);

        assertFalse("The request should be invalid when no search criteria are provided.", result);
    }
}
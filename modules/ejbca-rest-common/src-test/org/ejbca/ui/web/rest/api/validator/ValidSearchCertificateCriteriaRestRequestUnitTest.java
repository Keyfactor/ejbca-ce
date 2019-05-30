/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ui.web.rest.api.validator;

import org.ejbca.ui.web.rest.api.io.request.SearchCertificateCriteriaRestRequest;
import org.junit.Test;

import javax.validation.ConstraintViolation;
import javax.validation.Validation;
import javax.validation.Validator;
import java.util.Set;

import static org.junit.Assert.assertEquals;

/**
 * A unit test class for annotation @ValidSearchCertificateCriteriaRestRequest and its validator.
 *
 * @version $Id: ValidSearchCertificateCriteriaRestRequestUnitTest.java 29504 2018-07-17 17:55:12Z andrey_s_helmes $
 */
public class ValidSearchCertificateCriteriaRestRequestUnitTest {

    private static final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();

    @Test
    public void validationShouldFailOnNullProperty() {
        // given
        final String expectedMessage = "Invalid search criteria content, property cannot be null or empty.";
        final SearchCertificateCriteriaRestRequest testClass = SearchCertificateCriteriaRestRequest.builder()
                .property(null)
                .value("A")
                .operation("EQUAL")
                .build();
        // when
        final Set<ConstraintViolation<SearchCertificateCriteriaRestRequest>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals("Invalid object.",1, constraintViolations.size());
        assertEquals("Validation message should match.", expectedMessage, constraintViolations.iterator().next().getMessage());
    }

    @Test
    public void validationShouldFailOnEmptyProperty() {
        // given
        final String expectedMessage = "Invalid search criteria content, property cannot be null or empty.";
        final SearchCertificateCriteriaRestRequest testClass = SearchCertificateCriteriaRestRequest.builder()
                .property("")
                .value("A")
                .operation("EQUAL")
                .build();
        // when
        final Set<ConstraintViolation<SearchCertificateCriteriaRestRequest>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals("Invalid object.",1, constraintViolations.size());
        assertEquals("Validation message should match.", expectedMessage, constraintViolations.iterator().next().getMessage());
    }

    @Test
    public void validationShouldFailOnNullValue() {
        // given
        final String expectedMessage = "Invalid search criteria content, value cannot be null or empty.";
        final SearchCertificateCriteriaRestRequest testClass = SearchCertificateCriteriaRestRequest.builder()
                .property("CA")
                .value(null)
                .operation("EQUAL")
                .build();
        // when
        final Set<ConstraintViolation<SearchCertificateCriteriaRestRequest>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals("Invalid object.",1, constraintViolations.size());
        assertEquals("Validation message should match.", expectedMessage, constraintViolations.iterator().next().getMessage());
    }

    @Test
    public void validationShouldFailOnEmptyValue() {
        // given
        final String expectedMessage = "Invalid search criteria content, value cannot be null or empty.";
        final SearchCertificateCriteriaRestRequest testClass = SearchCertificateCriteriaRestRequest.builder()
                .property("CA")
                .value("")
                .operation("EQUAL")
                .build();
        // when
        final Set<ConstraintViolation<SearchCertificateCriteriaRestRequest>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals("Invalid object.",1, constraintViolations.size());
        assertEquals("Validation message should match.", expectedMessage, constraintViolations.iterator().next().getMessage());
    }

    @Test
    public void validationShouldFailOnNullOperation() {
        // given
        final String expectedMessage = "Invalid search criteria content, operation cannot be null or empty.";
        final SearchCertificateCriteriaRestRequest testClass = SearchCertificateCriteriaRestRequest.builder()
                .property("CA")
                .value("A")
                .operation(null)
                .build();
        // when
        final Set<ConstraintViolation<SearchCertificateCriteriaRestRequest>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals("Invalid object.",1, constraintViolations.size());
        assertEquals("Validation message should match.", expectedMessage, constraintViolations.iterator().next().getMessage());
    }

    @Test
    public void validationShouldFailOnEmptyOperation() {
        // given
        final String expectedMessage = "Invalid search criteria content, operation cannot be null or empty.";
        final SearchCertificateCriteriaRestRequest testClass = SearchCertificateCriteriaRestRequest.builder()
                .property("CA")
                .value("A")
                .operation("")
                .build();
        // when
        final Set<ConstraintViolation<SearchCertificateCriteriaRestRequest>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals("Invalid object.",1, constraintViolations.size());
        assertEquals("Validation message should match.", expectedMessage, constraintViolations.iterator().next().getMessage());
    }

    @Test
    public void validationShouldFailOnUnknownProperty() {
        // given
        final String expectedMessage = "Invalid search criteria's property, unrecognized.";
        final SearchCertificateCriteriaRestRequest testClass = SearchCertificateCriteriaRestRequest.builder()
                .property("BLAH")
                .value("A")
                .operation("EQUAL")
                .build();
        // when
        final Set<ConstraintViolation<SearchCertificateCriteriaRestRequest>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals("Invalid object.",1, constraintViolations.size());
        assertEquals("Validation message should match.", expectedMessage, constraintViolations.iterator().next().getMessage());
    }

    @Test
    public void validationShouldPassOnQUERYProperty() {
        // given
        final SearchCertificateCriteriaRestRequest testClass = SearchCertificateCriteriaRestRequest.builder()
                .property("QUERY")
                .value("A")
                .operation("EQUAL")
                .build();
        // when
        final Set<ConstraintViolation<SearchCertificateCriteriaRestRequest>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals("Valid object.",0, constraintViolations.size());
    }

    @Test
    public void validationShouldPassOnEND_ENTITY_PROFILEProperty() {
        // given
        final SearchCertificateCriteriaRestRequest testClass = SearchCertificateCriteriaRestRequest.builder()
                .property("END_ENTITY_PROFILE")
                .value("A")
                .operation("EQUAL")
                .build();
        // when
        final Set<ConstraintViolation<SearchCertificateCriteriaRestRequest>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals("Valid object.",0, constraintViolations.size());
    }

    @Test
    public void validationShouldPassOnCERTIFICATE_PROFILEProperty() {
        // given
        final SearchCertificateCriteriaRestRequest testClass = SearchCertificateCriteriaRestRequest.builder()
                .property("CERTIFICATE_PROFILE")
                .value("A")
                .operation("EQUAL")
                .build();
        // when
        final Set<ConstraintViolation<SearchCertificateCriteriaRestRequest>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals("Valid object.",0, constraintViolations.size());
    }

    @Test
    public void validationShouldPassOnCAProperty() {
        // given
        final SearchCertificateCriteriaRestRequest testClass = SearchCertificateCriteriaRestRequest.builder()
                .property("CA")
                .value("A")
                .operation("EQUAL")
                .build();
        // when
        final Set<ConstraintViolation<SearchCertificateCriteriaRestRequest>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals("Valid object.",0, constraintViolations.size());
    }

    @Test
    public void validationShouldPassOnSTATUSProperty() {
        // given
        final SearchCertificateCriteriaRestRequest testClass = SearchCertificateCriteriaRestRequest.builder()
                .property("STATUS")
                .value("CERT_ACTIVE")
                .operation("EQUAL")
                .build();
        // when
        final Set<ConstraintViolation<SearchCertificateCriteriaRestRequest>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals("Valid object.",0, constraintViolations.size());
    }

    @Test
    public void validationShouldPassOnISSUED_DATEProperty() {
        // given
        final SearchCertificateCriteriaRestRequest testClass = SearchCertificateCriteriaRestRequest.builder()
                .property("ISSUED_DATE")
                .value("2018-06-15T14:07:09Z")
                .operation("AFTER")
                .build();
        // when
        final Set<ConstraintViolation<SearchCertificateCriteriaRestRequest>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals("Valid object.",0, constraintViolations.size());
    }

    @Test
    public void validationShouldPassOnEXPIRE_DATEProperty() {
        // given
        final SearchCertificateCriteriaRestRequest testClass = SearchCertificateCriteriaRestRequest.builder()
                .property("EXPIRE_DATE")
                .value("2018-06-15T14:07:09Z")
                .operation("AFTER")
                .build();
        // when
        final Set<ConstraintViolation<SearchCertificateCriteriaRestRequest>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals("Valid object.",0, constraintViolations.size());
    }

    @Test
    public void validationShouldPassOnREVOCATION_DATEProperty() {
        // given
        final SearchCertificateCriteriaRestRequest testClass = SearchCertificateCriteriaRestRequest.builder()
                .property("REVOCATION_DATE")
                .value("2018-06-15T14:07:09Z")
                .operation("AFTER")
                .build();
        // when
        final Set<ConstraintViolation<SearchCertificateCriteriaRestRequest>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals("Valid object.",0, constraintViolations.size());
    }

    @Test
    public void validationShouldFailOnOperationAFTERMisuseForQUERY() {
        // given
        final String expectedMessage = "Invalid search criteria's operation, should be EQUAL or LIKE.";
        final SearchCertificateCriteriaRestRequest testClass = SearchCertificateCriteriaRestRequest.builder()
                .property("QUERY")
                .value("1")
                .operation("AFTER")
                .build();
        // when
        final Set<ConstraintViolation<SearchCertificateCriteriaRestRequest>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals("Invalid object.",1, constraintViolations.size());
        assertEquals("Validation message should match.", expectedMessage, constraintViolations.iterator().next().getMessage());
    }

    @Test
    public void validationShouldFailOnOperationAFTERMisuseForEND_ENTITY_PROFILE() {
        // given
        final String expectedMessage = "Invalid search criteria's operation, should be EQUAL.";
        final SearchCertificateCriteriaRestRequest testClass = SearchCertificateCriteriaRestRequest.builder()
                .property("END_ENTITY_PROFILE")
                .value("1")
                .operation("AFTER")
                .build();
        // when
        final Set<ConstraintViolation<SearchCertificateCriteriaRestRequest>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals("Invalid object.",1, constraintViolations.size());
        assertEquals("Validation message should match.", expectedMessage, constraintViolations.iterator().next().getMessage());
    }

    @Test
    public void validationShouldFailOnOperationBEFOREMisuseForPropertyEND_ENTITY_PROFILE() {
        // given
        final String expectedMessage = "Invalid search criteria's operation, should be EQUAL.";
        final SearchCertificateCriteriaRestRequest testClass = SearchCertificateCriteriaRestRequest.builder()
                .property("END_ENTITY_PROFILE")
                .value("1")
                .operation("BEFORE")
                .build();
        // when
        final Set<ConstraintViolation<SearchCertificateCriteriaRestRequest>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals("Invalid object.",1, constraintViolations.size());
        assertEquals("Validation message should match.", expectedMessage, constraintViolations.iterator().next().getMessage());
    }

    @Test
    public void validationShouldFailOnOperationEQUALMisuse() {
        // given
        final String expectedMessage = "Invalid search criteria's operation, should be AFTER or BEFORE.";
        final SearchCertificateCriteriaRestRequest testClass = SearchCertificateCriteriaRestRequest.builder()
                .property("ISSUED_DATE")
                .value("2018-06-15T14:07:09Z")
                .operation("EQUAL")
                .build();
        // when
        final Set<ConstraintViolation<SearchCertificateCriteriaRestRequest>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals("Invalid object.",1, constraintViolations.size());
        assertEquals("Validation message should match.", expectedMessage, constraintViolations.iterator().next().getMessage());
    }

    @Test
    public void validationShouldFailOnOperationLIKEMisuse() {
        // given
        final String expectedMessage = "Invalid search criteria's operation, should be AFTER or BEFORE.";
        final SearchCertificateCriteriaRestRequest testClass = SearchCertificateCriteriaRestRequest.builder()
                .property("ISSUED_DATE")
                .value("2018-06-15T14:07:09Z")
                .operation("LIKE")
                .build();
        // when
        final Set<ConstraintViolation<SearchCertificateCriteriaRestRequest>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals("Invalid object.",1, constraintViolations.size());
        assertEquals("Validation message should match.", expectedMessage, constraintViolations.iterator().next().getMessage());
    }

    @Test
    public void validationShouldFailOnUnknownOperation() {
        // given
        final String expectedMessage = "Invalid search criteria's operation, unrecognized.";
        final SearchCertificateCriteriaRestRequest testClass = SearchCertificateCriteriaRestRequest.builder()
                .property("END_ENTITY_PROFILE")
                .value("A")
                .operation("BLAH")
                .build();
        // when
        final Set<ConstraintViolation<SearchCertificateCriteriaRestRequest>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals("Invalid object.",1, constraintViolations.size());
        assertEquals("Validation message should match.", expectedMessage, constraintViolations.iterator().next().getMessage());
    }

    @Test
    public void validationShouldFailOnValueWithImproperDate() {
        // given
        final String expectedMessage = "Invalid search criteria content, value does not contain proper date.";
        final SearchCertificateCriteriaRestRequest testClass = SearchCertificateCriteriaRestRequest.builder()
                .property("ISSUED_DATE")
                .value("20180615T140709Z")
                .operation("AFTER")
                .build();
        // when
        final Set<ConstraintViolation<SearchCertificateCriteriaRestRequest>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals("Invalid object.",1, constraintViolations.size());
        assertEquals("Validation message should match.", expectedMessage, constraintViolations.iterator().next().getMessage());
    }

    @Test
    public void validationShouldFailOnValueWithImproperInteger() {
        // given
        final SearchCertificateCriteriaRestRequest testClass = SearchCertificateCriteriaRestRequest.builder()
                .property("END_ENTITY_PROFILE")
                .value("A")
                .operation("EQUAL")
                .build();
        // when
        final Set<ConstraintViolation<SearchCertificateCriteriaRestRequest>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals("Valid object.",0, constraintViolations.size());
    }

    @Test
    public void validationShouldFailOnUnknownCertificateStatusValue() {
        // given
        final String expectedMessage = "Invalid search criteria content, value does not contain certificate status.";
        final SearchCertificateCriteriaRestRequest testClass = SearchCertificateCriteriaRestRequest.builder()
                .property("STATUS")
                .value("BLAH")
                .operation("EQUAL")
                .build();
        // when
        final Set<ConstraintViolation<SearchCertificateCriteriaRestRequest>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals("Valid object.",1, constraintViolations.size());
        assertEquals("Validation message should match.", expectedMessage, constraintViolations.iterator().next().getMessage());
    }

    @Test
    public void validationShouldPassOnSTATUSPropertyWithValueCERT_REVOKED() {
        // given
        final SearchCertificateCriteriaRestRequest testClass = SearchCertificateCriteriaRestRequest.builder()
                .property("STATUS")
                .value("CERT_REVOKED")
                .operation("EQUAL")
                .build();
        // when
        final Set<ConstraintViolation<SearchCertificateCriteriaRestRequest>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals("Valid object.",0, constraintViolations.size());
    }

    @Test
    public void validationShouldPassOnSTATUSPropertyWithValueREVOCATION_REASON_UNSPECIFIED() {
        // given
        final SearchCertificateCriteriaRestRequest testClass = SearchCertificateCriteriaRestRequest.builder()
                .property("STATUS")
                .value("REVOCATION_REASON_UNSPECIFIED")
                .operation("EQUAL")
                .build();
        // when
        final Set<ConstraintViolation<SearchCertificateCriteriaRestRequest>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals("Valid object.",0, constraintViolations.size());
    }

    @Test
    public void validationShouldPassOnSTATUSPropertyWithValueREVOCATION_REASON_KEYCOMPROMISE() {
        // given
        final SearchCertificateCriteriaRestRequest testClass = SearchCertificateCriteriaRestRequest.builder()
                .property("STATUS")
                .value("REVOCATION_REASON_KEYCOMPROMISE")
                .operation("EQUAL")
                .build();
        // when
        final Set<ConstraintViolation<SearchCertificateCriteriaRestRequest>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals("Valid object.",0, constraintViolations.size());
    }

    @Test
    public void validationShouldPassOnSTATUSPropertyWithValueREVOCATION_REASON_CACOMPROMISE() {
        // given
        final SearchCertificateCriteriaRestRequest testClass = SearchCertificateCriteriaRestRequest.builder()
                .property("STATUS")
                .value("REVOCATION_REASON_CACOMPROMISE")
                .operation("EQUAL")
                .build();
        // when
        final Set<ConstraintViolation<SearchCertificateCriteriaRestRequest>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals("Valid object.",0, constraintViolations.size());
    }

    @Test
    public void validationShouldPassOnSTATUSPropertyWithValueREVOCATION_REASON_AFFILIATIONCHANGED() {
        // given
        final SearchCertificateCriteriaRestRequest testClass = SearchCertificateCriteriaRestRequest.builder()
                .property("STATUS")
                .value("REVOCATION_REASON_AFFILIATIONCHANGED")
                .operation("EQUAL")
                .build();
        // when
        final Set<ConstraintViolation<SearchCertificateCriteriaRestRequest>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals("Valid object.",0, constraintViolations.size());
    }

    @Test
    public void validationShouldPassOnSTATUSPropertyWithValueREVOCATION_REASON_SUPERSEDED() {
        // given
        final SearchCertificateCriteriaRestRequest testClass = SearchCertificateCriteriaRestRequest.builder()
                .property("STATUS")
                .value("REVOCATION_REASON_SUPERSEDED")
                .operation("EQUAL")
                .build();
        // when
        final Set<ConstraintViolation<SearchCertificateCriteriaRestRequest>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals("Valid object.",0, constraintViolations.size());
    }

    @Test
    public void validationShouldPassOnSTATUSPropertyWithValueREVOCATION_REASON_CESSATIONOFOPERATION() {
        // given
        final SearchCertificateCriteriaRestRequest testClass = SearchCertificateCriteriaRestRequest.builder()
                .property("STATUS")
                .value("REVOCATION_REASON_CESSATIONOFOPERATION")
                .operation("EQUAL")
                .build();
        // when
        final Set<ConstraintViolation<SearchCertificateCriteriaRestRequest>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals("Valid object.",0, constraintViolations.size());
    }

    @Test
    public void validationShouldPassOnSTATUSPropertyWithValueREVOCATION_REASON_CERTIFICATEHOLD() {
        // given
        final SearchCertificateCriteriaRestRequest testClass = SearchCertificateCriteriaRestRequest.builder()
                .property("STATUS")
                .value("REVOCATION_REASON_CERTIFICATEHOLD")
                .operation("EQUAL")
                .build();
        // when
        final Set<ConstraintViolation<SearchCertificateCriteriaRestRequest>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals("Valid object.",0, constraintViolations.size());
    }

    @Test
    public void validationShouldPassOnSTATUSPropertyWithValueREVOCATION_REASON_REMOVEFROMCRL() {
        // given
        final SearchCertificateCriteriaRestRequest testClass = SearchCertificateCriteriaRestRequest.builder()
                .property("STATUS")
                .value("REVOCATION_REASON_REMOVEFROMCRL")
                .operation("EQUAL")
                .build();
        // when
        final Set<ConstraintViolation<SearchCertificateCriteriaRestRequest>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals("Valid object.",0, constraintViolations.size());
    }

    @Test
    public void validationShouldPassOnSTATUSPropertyWithValueREVOCATION_REASON_PRIVILEGESWITHDRAWN() {
        // given
        final SearchCertificateCriteriaRestRequest testClass = SearchCertificateCriteriaRestRequest.builder()
                .property("STATUS")
                .value("REVOCATION_REASON_PRIVILEGESWITHDRAWN")
                .operation("EQUAL")
                .build();
        // when
        final Set<ConstraintViolation<SearchCertificateCriteriaRestRequest>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals("Valid object.",0, constraintViolations.size());
    }

    @Test
    public void validationShouldPassOnSTATUSPropertyWithValueREVOCATION_REASON_AACOMPROMISE() {
        // given
        final SearchCertificateCriteriaRestRequest testClass = SearchCertificateCriteriaRestRequest.builder()
                .property("STATUS")
                .value("REVOCATION_REASON_AACOMPROMISE")
                .operation("EQUAL")
                .build();
        // when
        final Set<ConstraintViolation<SearchCertificateCriteriaRestRequest>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals("Valid object.",0, constraintViolations.size());
    }

    @Test
    public void validationShouldFailOnStatusPropertyWithOperationAFTERMisuse() {
        // given
        final String expectedMessage = "Invalid search criteria's operation, should be EQUAL.";
        final SearchCertificateCriteriaRestRequest testClass = SearchCertificateCriteriaRestRequest.builder()
                .property("STATUS")
                .value("CERT_ACTIVE")
                .operation("AFTER")
                .build();
        // when
        final Set<ConstraintViolation<SearchCertificateCriteriaRestRequest>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals("Invalid object.",1, constraintViolations.size());
        assertEquals("Validation message should match.", expectedMessage, constraintViolations.iterator().next().getMessage());
    }

    @Test
    public void validationShouldFailOnStatusPropertyWithOperationBEFOREMisuse() {
        // given
        final String expectedMessage = "Invalid search criteria's operation, should be EQUAL.";
        final SearchCertificateCriteriaRestRequest testClass = SearchCertificateCriteriaRestRequest.builder()
                .property("STATUS")
                .value("CERT_ACTIVE")
                .operation("BEFORE")
                .build();
        // when
        final Set<ConstraintViolation<SearchCertificateCriteriaRestRequest>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals("Invalid object.",1, constraintViolations.size());
        assertEquals("Validation message should match.", expectedMessage, constraintViolations.iterator().next().getMessage());
    }

}

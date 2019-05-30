/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/

package org.ejbca.ui.web.rest.api.Assert;

import static org.junit.Assert.assertEquals;

import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

/**
 * A set of assertion methods useful for writing EJBCA REST API tests. Only failed assertions are thrown.
 *
 * @version $Id: EjbcaAssert.java 29080 2018-05-31 11:12:13Z andrey_s_helmes $
 */
public class EjbcaAssert {

    public static final String HEADER_CONTENT_TYPE = "content-type";
    // JSON properties
    public static final String JSON_PROPERTY_STATUS = "status";
    public static final String JSON_PROPERTY_VERSION = "version";
    public static final String JSON_PROPERTY_REVISION = "revision";
    //
    public static final String JSON_PROPERTY_ERROR_CODE = "error_code";
    public static final String JSON_PROPERTY_ERROR_MESSAGE = "error_message";
    //
    public static final String JSON_PROPERTY_STATUS_CODE = "status_code";
    public static final String JSON_PROPERTY_INFO_MESSAGE = "info_message";
    //
    private static final JSONParser jsonParser = new JSONParser();

    /**
     * Asserts that a content-type is 'application/json'. If it is not it throws an AssertionError.
     *
     * @param response Response object.
     */
    public static void assertJsonContentType(final Response response) {
        if(response == null) {
            throw new AssertionError("Response is null.");
        }
        final MultivaluedMap<String, Object> headersMap = response.getMetadata();
        if (headersMap == null) {
            throw new AssertionError("Response does not contain headers.");
        }
        boolean foundContentTypeHeader = false;
        for(String headerName : headersMap.keySet()) {
            if(HEADER_CONTENT_TYPE.equalsIgnoreCase(headerName)) {
                final String actualContentType = headersMap.getFirst(headerName).toString();
                assertEquals("", MediaType.APPLICATION_JSON, actualContentType);
                foundContentTypeHeader = true;
                break;
            }
        }
        if(!foundContentTypeHeader) {
            throw new AssertionError("Content-type is not defined.");
        }
    }

    /**
     * Asserts that an input JSON contains non-null JSON properties. If it is not it throws an AssertionError.
     *
     * @param expectedStatus expected status property's value.
     * @param expectedVersion expected version property's value.
     * @param expectedRevision expected revision property's value.
     * @param actualJsonString input JSON.
     */
    public static void assertProperJsonStatusResponse(final String expectedStatus, final String expectedVersion, final String expectedRevision, final String actualJsonString) {
        final JSONObject actualJsonObject = assertNotNullJsonObject(actualJsonString);
        assertEqualJsonPropertyAsString(actualJsonObject, JSON_PROPERTY_STATUS, expectedStatus);
        assertEqualJsonPropertyAsString(actualJsonObject, JSON_PROPERTY_VERSION, expectedVersion);
        assertEqualJsonPropertyAsString(actualJsonObject, JSON_PROPERTY_REVISION, expectedRevision);
    }

    /**
     * Asserts that an input JSON contains non-null JSON properties. If it is not it throws an AssertionError.
     *
     * @param expectedErrorCode expected error code property's value.
     * @param expectedErrorMessage expected error message property's value.
     * @param actualJsonString input JSON.
     */
    public static void assertProperJsonExceptionErrorResponse(final long expectedErrorCode, final String expectedErrorMessage, final String actualJsonString) {
        final JSONObject actualJsonObject = assertNotNullJsonObject(actualJsonString);
        assertEqualJsonPropertyAsLong(actualJsonObject, JSON_PROPERTY_ERROR_CODE, expectedErrorCode);
        assertEqualJsonPropertyAsString(actualJsonObject, JSON_PROPERTY_ERROR_MESSAGE, expectedErrorMessage);
    }

    /**
     * Asserts that an input JSON contains non-null JSON properties. If it is not it throws an AssertionError.
     *
     * @param expectedInfoCode expected info code property's value.
     * @param expectedInfoMessage expected info message property's value.
     * @param actualJsonString input JSON.
     */
    public static void assertProperJsonExceptionInfoResponse(final long expectedInfoCode, final String expectedInfoMessage, final String actualJsonString) {
        final JSONObject actualJsonObject = assertNotNullJsonObject(actualJsonString);
        assertEqualJsonPropertyAsLong(actualJsonObject, JSON_PROPERTY_STATUS_CODE, expectedInfoCode);
        assertEqualJsonPropertyAsString(actualJsonObject, JSON_PROPERTY_INFO_MESSAGE, expectedInfoMessage);
    }

    /**
     * Asserts that an input JSON contains non-null valid JSONObject. If it is not it throws an AssertionError.
     *
     * @param actualJsonString input JSON.
     *
     * @return a JSONObject from the input JSON.
     */
    public static JSONObject assertNotNullJsonObject(final String actualJsonString) {
        if(actualJsonString == null) {
            throw new AssertionError("Actual JSON is null.");
        }
        try {
            return (JSONObject) jsonParser.parse(actualJsonString);
        }
        catch (ParseException parseException) {
            throw new AssertionError("Cannot parse the JSON [" + actualJsonString + "].");
        }
    }

    /**
     * Asserts that an input JSONObject contains non-null JSON property with expected value. If it is not it throws an AssertionError.
     *
     * @param actualJsonObject input JSONObject.
     * @param jsonPropertyName expected JSON property.
     * @param expectedValue expected JSON property's value.
     */
    public static void assertEqualJsonPropertyAsLong(final JSONObject actualJsonObject, final String jsonPropertyName, long expectedValue) {
        final Object actualPropertyObject = actualJsonObject.get(jsonPropertyName);
        if(actualPropertyObject == null) {
            throw new AssertionError("Actual [" + jsonPropertyName + "] is null.");
        }
        if(!(actualPropertyObject instanceof Long)) {
            throw new AssertionError("Actual [" + jsonPropertyName + "] is not long.");
        }
        if(expectedValue != (Long) actualPropertyObject) {
            throw new AssertionError("Actual [" + actualPropertyObject + "] does not match the expected [" + expectedValue + "].");
        }
    }

    /**
     * Asserts that an input JSONObject contains non-null JSON property with expected value. If it is not it throws an AssertionError.
     *
     * @param actualJsonObject input JSONObject.
     * @param jsonPropertyName expected JSON property.
     * @param expectedValue expected JSON property's value.
     */
    public static void assertEqualJsonPropertyAsString(final JSONObject actualJsonObject, final String jsonPropertyName, String expectedValue) {
        final Object actualPropertyObject = actualJsonObject.get(jsonPropertyName);
        if(actualPropertyObject == null) {
            throw new AssertionError("Actual [" + jsonPropertyName + "] is null.");
        }
        if(!expectedValue.equals(actualPropertyObject)) {
            throw new AssertionError("Actual [" + actualPropertyObject + "] does not match the expected [" + expectedValue + "].");
        }
    }

}

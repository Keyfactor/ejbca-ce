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

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * A class representing the information about an exceptional event triggered by REST resource failure.
 *
 * @version $Id: ExceptionErrorRestResponse.java 29294 2018-06-21 07:10:35Z tarmo_r_helmes $
 */
public class ExceptionErrorRestResponse {

    // Have to match HTTP Status codes
    @Schema(description = "Error code indicating the type of error", example = "400")
    private int errorCode;
    @Schema(description = "Detailed error message", example = "CA with DN: CN=FakeCA does not exist.")
    private String errorMessage;

    /**
     * Simple constructor.
     */
    public ExceptionErrorRestResponse() {}

    private ExceptionErrorRestResponse(final int errorCode, final String errorMessage) {
        this.errorCode = errorCode;
        this.errorMessage = errorMessage;
    }

    /**
     * Return the numeric value of error code.
     *
     * @return numeric value of error code.
     */
    public int getErrorCode() {
        return errorCode;
    }

    /**
     * Sets a numeric value of error code.
     * <br/>
     * <b>Note:</b> should match standard HTTP response codes.
     *
     * @param errorCode numeric value of error code.
     */
    public void setErrorCode(int errorCode) {
        this.errorCode = errorCode;
    }

    /**
     * Return the error message.
     *
     * @return error message.
     */
    public String getErrorMessage() {
        return errorMessage;
    }

    /**
     * Sets an error message.
     *
     * @param errorMessage error message.
     */
    public void setErrorMessage(String errorMessage) {
        this.errorMessage = errorMessage;
    }

    /**
     * Return a builder instance for this class.
     *
     * @return builder instance for this class.
     */
    public static ExceptionErrorRestResponseBuilder builder() {
        return new ExceptionErrorRestResponseBuilder();
    }

    /**
     * Builder of this class.
     */
    public static class ExceptionErrorRestResponseBuilder {

        private int errorCode;
        private String errorMessage;

        ExceptionErrorRestResponseBuilder() {
        }

        /**
         * Sets a numeric value of error code in this builder.
         *
         * @param errorCode numeric value of error code.
         *
         * @return instance of this builder.
         */
        public ExceptionErrorRestResponseBuilder errorCode(final int errorCode) {
            this.errorCode = errorCode;
            return this;
        }

        /**
         * Sets an error message in this builder.
         *
         * @param errorMessage error message.
         *
         * @return instance of this builder.
         */
        public ExceptionErrorRestResponseBuilder errorMessage(final String errorMessage) {
            this.errorMessage = errorMessage;
            return this;
        }

        /**
         * Builds an instance of ExceptionErrorRestResponseBuilder using this builder.
         *
         * @return instance of ExceptionErrorRestResponseBuilder using this builder.
         */
        public ExceptionErrorRestResponse build() {
            return new ExceptionErrorRestResponse(errorCode, errorMessage);
        }
    }
}

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

/**
 * A class representing the information about an exceptional event triggered by REST resource failure.
 *
 * @version $Id: ExceptionInfoRestResponse.java 28909 2018-05-10 12:16:53Z andrey_s_helmes $
 */
public class ExceptionInfoRestResponse {

    // Have to match HTTP Status codes
    private int errorCode;
    private String errorMessage;

    /**
     * Simple constructor.
     */
    public ExceptionInfoRestResponse() {
    }

    private ExceptionInfoRestResponse(final int errorCode, final String errorMessage) {
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
     * @param errorCode umeric value of error code.
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
    public static ExceptionInfoTypeBuilder builder() {
        return new ExceptionInfoTypeBuilder();
    }

    /**
     * Builder of this class.
     */
    public static class ExceptionInfoTypeBuilder {

        private int errorCode;
        private String errorMessage;

        ExceptionInfoTypeBuilder() {
        }

        /**
         * Sets a numeric value of error code in this builder.
         *
         * @param errorCode numeric value of error code.
         *
         * @return instance of this builder.
         */
        public ExceptionInfoTypeBuilder errorCode(final int errorCode) {
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
        public ExceptionInfoTypeBuilder errorMessage(final String errorMessage) {
            this.errorMessage = errorMessage;
            return this;
        }

        /**
         * Builds an instance of ExceptionInfoRestResponse using this builder.
         *
         * @return instance of ExceptionInfoRestResponse using this builder.
         */
        public ExceptionInfoRestResponse build() {
            return new ExceptionInfoRestResponse(errorCode, errorMessage);
        }
    }
}

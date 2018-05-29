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
 * A class representing the information about an "expected" exceptional event triggered by REST resource failure,
 * such as WaitingForApprovalException which shouldn't be considered an error. In order to respond to "error events"
 * use ExceptionErrorRestResponse.
 * @see org.ejbca.ui.web.rest.api.io.response.ExceptionErrorRestResponse
 * @version $Id$
 *
 */
public class ExceptionInfoRestResponse {

    // Have to match HTTP Status codes
    private int statusCode;
    private String infoMessage;

    /**
     * Simple constructor.
     */
    public ExceptionInfoRestResponse() {}

    private ExceptionInfoRestResponse(final int statusCode, final String infoMessage) {
        this.statusCode = statusCode;
        this.infoMessage = infoMessage;
    }
    
    /**
     * @return the numeric value of status code.
     */
    public int getStatusCode() {
        return statusCode;
    }

    /**
     * Sets a numeric value of status code.
     * <br/>
     * <b>Note:</b> should match standard HTTP response codes.
     *
     * @param statusCode numeric value of status code.
     */
    public void setStatusCode(int statusCode) {
        this.statusCode = statusCode;
    }

    /**
     * @return info message
     */
    public String getInfoMessage() {
        return infoMessage;
    }

    /**
     * @param infoMessage info message
     */
    public void setInfoMessage(String infoMessage) {
        this.infoMessage = infoMessage;
    }

    
    /**
     * @return builder instance for this class.
     */
    public static ExceptionInfoTypeBuilder builder() {
        return new ExceptionInfoTypeBuilder();
    }
    
    /**
     * Builder of this class.
     */
    public static class ExceptionInfoTypeBuilder {

        private int statusCode;
        private String infoMessage;

        ExceptionInfoTypeBuilder() {
        }

        /**
         * Sets a numeric value of status code in this builder.
         *
         * @param statusCode numeric value of status code.
         *
         * @return instance of this builder.
         */
        public ExceptionInfoTypeBuilder statusCode(final int statusCode) {
            this.statusCode = statusCode;
            return this;
        }

        /**
         * Sets an info message in this builder.
         *
         * @param infoMessage info message.
         *
         * @return instance of this builder.
         */
        public ExceptionInfoTypeBuilder infoMessage(final String infoMessage) {
            this.infoMessage = infoMessage;
            return this;
        }

        /**
         * Builds an instance of ExceptionInfoRestResponse using this builder.
         *
         * @return instance of ExceptionInfoRestResponse using this builder.
         */
        public ExceptionInfoRestResponse build() {
            return new ExceptionInfoRestResponse(statusCode, infoMessage);
        }
    }
}
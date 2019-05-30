/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/

package org.ejbca.ui.web.rest.api.io.response;

import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * A class representing the information about an "expected" exceptional event triggered by REST resource,
 * such as WaitingForApprovalException which shouldn't be considered an error. In order to respond to "error events"
 * use ExceptionErrorRestResponse.
 * @see org.ejbca.ui.web.rest.api.io.response.ExceptionErrorRestResponse
 *
 * @version $Id: ExceptionInfoRestResponse.java 29010 2018-05-23 13:09:53Z andrey_s_helmes
 *
 */
public class ExceptionInfoRestResponse {

    // Have to match HTTP Status codes
    private int statusCode;
    private String infoMessage;
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String link;

    /**
     * Simple constructor.
     */
    public ExceptionInfoRestResponse() {}

    private ExceptionInfoRestResponse(final int statusCode, final String infoMessage, final String link) {
        this.statusCode = statusCode;
        this.infoMessage = infoMessage;
        this.link = link;
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
     * Returns the link used to finalize the enrollment after approval
     * @return link to end point
     */
    public String getLink() {
        return link;
    }

    /**
     * Set the link used to finalize the enrollment after approval
     * @param link to end point
     */
    public void setLink(String link) {
        this.link = link;
    }

    /**
     * @return builder instance for this class.
     */
    public static ExceptionInfoRestResponseBuilder builder() {
        return new ExceptionInfoRestResponseBuilder();
    }
    
    /**
     * Builder of this class.
     */
    public static class ExceptionInfoRestResponseBuilder {

        private int statusCode;
        private String infoMessage;
        private String link;

        ExceptionInfoRestResponseBuilder() {
        }

        /**
         * Sets a numeric value of status code in this builder.
         *
         * @param statusCode numeric value of status code.
         *
         * @return instance of this builder.
         */
        public ExceptionInfoRestResponseBuilder statusCode(final int statusCode) {
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
        public ExceptionInfoRestResponseBuilder infoMessage(final String infoMessage) {
            this.infoMessage = infoMessage;
            return this;
        }

        /**
         * Set the link used to finalize the enrollment after approval
         * @param link to end point
         * @return instance of this builder.
         */
        public ExceptionInfoRestResponseBuilder link(final String link) {
            this.link = link;
            return this;
        }
        
        /**
         * Builds an instance of ExceptionInfoRestResponse using this builder.
         *
         * @return instance of ExceptionInfoRestResponse using this builder.
         */
        public ExceptionInfoRestResponse build() {
            return new ExceptionInfoRestResponse(statusCode, infoMessage, link);
        }
    }
}
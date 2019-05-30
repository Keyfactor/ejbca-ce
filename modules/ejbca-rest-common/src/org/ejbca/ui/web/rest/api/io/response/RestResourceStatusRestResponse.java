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

/**
 * A class representing the status information of a REST resource.
 *
 * @version $Id: RestResourceStatusRestResponse.java 28909 2018-05-10 12:16:53Z andrey_s_helmes $
 */
public class RestResourceStatusRestResponse {

    private String status;
    private String version;
    private String revision;
    // TODO Possible extra info: Authentication info, token information, token validity and etc.

    public RestResourceStatusRestResponse() {
    }

    private RestResourceStatusRestResponse(String status, String version, String revision) {
        this.status = status;
        this.version = version;
        this.revision = revision;
    }

    /**
     * Returns the status.
     *
     * @return status.
     */
    public String getStatus() {
        return status;
    }

    /**
     * Sets a status.
     *
     * @param status status.
     */
    public void setStatus(String status) {
        this.status = status;
    }

    /**
     * Returns the version.
     *
     * @return version.
     */
    public String getVersion() {
        return version;
    }

    /**
     * Sets a version.
     *
     * @param version version.
     */
    public void setVersion(String version) {
        this.version = version;
    }

    /**
     * Returns the revision.
     *
     * @return revision.
     */
    public String getRevision() {
        return revision;
    }

    /**
     * Sets a revision.
     *
     * @param revision revision.
     */
    public void setRevision(String revision) {
        this.revision = revision;
    }

    /**
     * Returns a builder instance for this class.
     *
     * @return an instance of builder for this class.
     */
    public static RestResourceStatusRestResponseBuilder builder() {
        return new RestResourceStatusRestResponseBuilder();
    }

    /**
     * Builder of this class.
     */
    public static class RestResourceStatusRestResponseBuilder {

        private String status;
        private String version;
        private String revision;

        RestResourceStatusRestResponseBuilder() {
        }

        /**
         * Sets a status of RestResourceStatusRestResponse in this builder.
         *
         * @param status status.
         *
         * @return instance of this builder.
         */
        public RestResourceStatusRestResponseBuilder status(final String status) {
            this.status = status;
            return this;
        }

        /**
         * Sets a version of RestResourceStatusRestResponse in this builder.
         *
         * @param version version.
         *
         * @return instance of this builder.
         */
        public RestResourceStatusRestResponseBuilder version(final String version) {
            this.version = version;
            return this;
        }

        /**
         * Sets a version of RestResourceStatusRestResponse in this builder.
         *
         * @param revision revision.
         *
         * @return instance of this builder.
         */
        public RestResourceStatusRestResponseBuilder revision(final String revision) {
            this.revision = revision;
            return this;
        }

        /**
         * Builds an instance of RestResourceStatusRestResponse using this builder.
         *
         * @return instance of RestResourceStatusRestResponse using this builder.
         */
        public RestResourceStatusRestResponse build() {
            return new RestResourceStatusRestResponse(
                    status,
                    version,
                    revision
            );
        }
    }

}

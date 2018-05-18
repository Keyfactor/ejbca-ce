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
package org.ejbca.ui.web.rest.api.types;

/**
 * A class representing the status information of a REST resource.
 *
 * @version $Id: RestServiceStatusType.java 28909 2018-05-10 12:16:53Z andrey_s_helmes $
 */
public class RestServiceStatusType {

    private String status;
    private String version;
    private String revision;
    // TODO Possible extra info: Authentication info, token information, token validity and etc.

    public RestServiceStatusType() {
    }

    private RestServiceStatusType(String status, String version, String revision) {
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
    public static RestResourceStatusTypeBuilder builder() {
        return new RestResourceStatusTypeBuilder();
    }

    /**
     * Builder of this class.
     */
    public static class RestResourceStatusTypeBuilder {

        private String status;
        private String version;
        private String revision;

        RestResourceStatusTypeBuilder() {
        }

        /**
         * Sets a status of RestResourceStatusType in this builder.
         *
         * @param status status.
         *
         * @return instance of this builder.
         */
        public RestResourceStatusTypeBuilder status(final String status) {
            this.status = status;
            return this;
        }

        /**
         * Sets a version of RestResourceStatusType in this builder.
         *
         * @param version version.
         *
         * @return instance of this builder.
         */
        public RestResourceStatusTypeBuilder version(final String version) {
            this.version = version;
            return this;
        }

        /**
         * Sets a version of RestResourceStatusType in this builder.
         *
         * @param revision revision.
         *
         * @return instance of this builder.
         */
        public RestResourceStatusTypeBuilder revision(final String revision) {
            this.revision = revision;
            return this;
        }

        /**
         * Builds an instance of RestServiceStatusType using this builder.
         *
         * @return instance of RestServiceStatusType using this builder.
         */
        public RestServiceStatusType build() {
            return new RestServiceStatusType(
                    status,
                    version,
                    revision
            );
        }
    }

}

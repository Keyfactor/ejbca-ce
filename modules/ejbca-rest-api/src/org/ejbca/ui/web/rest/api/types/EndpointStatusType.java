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

// TODO Javadoc
/**
 * A class representing the status information of an endpoint.
 *
 * @version $Id: EndpointStatusType.java 28909 2018-05-10 12:16:53Z aminkh $
 */
public class EndpointStatusType {

    private String status;
    private String version;
    private String revision;
    // TODO Possible extra info: Authentication info, token information, token validity and etc.

    public EndpointStatusType() {
    }

    EndpointStatusType(String status, String version, String revision) {
        this.status = status;
        this.version = version;
        this.revision = revision;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public String getRevision() {
        return revision;
    }

    public void setRevision(String revision) {
        this.revision = revision;
    }

    public static EndpointStatusTypeBuilder builder() {
        return new EndpointStatusTypeBuilder();
    }

    public static class EndpointStatusTypeBuilder {

        private String status;
        private String version;
        private String revision;

        EndpointStatusTypeBuilder() {
        }

        public EndpointStatusTypeBuilder status(final String status) {
            this.status = status;
            return this;
        }

        public EndpointStatusTypeBuilder version(final String version) {
            this.version = version;
            return this;
        }

        public EndpointStatusTypeBuilder revision(final String revision) {
            this.revision = revision;
            return this;
        }

        public EndpointStatusType build() {
            return new EndpointStatusType(
                    status,
                    version,
                    revision
            );
        }
    }

}

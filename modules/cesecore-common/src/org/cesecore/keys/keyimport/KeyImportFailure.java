/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.keys.keyimport;

import java.io.Serializable;

/**
 * Holds information about a failed key import. Does not contain the actual key.
 */
public class KeyImportFailure implements Serializable {

    private static final long serialVersionUID = 1L;

    private String username;
    private KeyImportFailureReason reason = KeyImportFailureReason.GENERAL_ERROR;

    public KeyImportFailure() {

    }

    public KeyImportFailure(final String username, final KeyImportFailureReason reason) {
        this.username = username;
        this.reason = reason;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public KeyImportFailureReason getReason() {
        return reason;
    }

    public void setReason(KeyImportFailureReason reason) {
        this.reason = reason;
    }
}

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

import com.keyfactor.util.StringTools;

import java.io.Serializable;

/**
 * Holds data about a single keystore in the key import process.
 */
public class KeyImportKeystoreData implements Serializable {

    private static final long serialVersionUID = 1L;

    private String username;
    private String password;
    private String keystore;

    public KeyImportKeystoreData(final String username, final String password, final String keystore) {
        this.username = username;
        this.password = StringTools.putBase64String(password);
        this.keystore = keystore;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return StringTools.getBase64String(password);
    }

    public void setPassword(String password) {
        this.password = StringTools.putBase64String(password);
    }

    public String getKeystore() {
        return keystore;
    }

    public void setKeystore(String keystore) {
        this.keystore = keystore;
    }
}

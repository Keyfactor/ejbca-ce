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
package org.ejbca.ui.web.rest.api.io.request;

import io.swagger.v3.oas.annotations.media.Schema;

public class KeystoreRestRequestComponent {
    @Schema(description = "Username. New or existing end entity name", example = "JohnDoe")
    private String username;
    @Schema(description = "Keystore bytes (base64)", example = "MIACaMQwqALD...452MRTqwsTR=")
    private String keystore;
    @Schema(description = "Password to p12", example = "foo123")
    private String password;

    private KeystoreRestRequestComponent() {
    }

    private KeystoreRestRequestComponent(String username, String keystore, String password) {
        this.username = username;
        this.keystore = keystore;
        this.password = password;
    }

    public String getUsername() {
        return username;
    }

    public String getKeystore() {
        return keystore;
    }

    public String getPassword() {
        return password;
    }

    public static KeystoreRestRequestComponent create(String username, String keystore, String password) {
        return new KeystoreRestRequestComponent(username, keystore, password);
    }
}

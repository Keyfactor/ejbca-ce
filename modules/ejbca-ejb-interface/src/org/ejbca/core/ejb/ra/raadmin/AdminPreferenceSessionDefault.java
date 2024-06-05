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
 
 
package org.ejbca.core.ejb.ra.raadmin;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.PublicAccessAuthenticationToken;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationToken;

import com.keyfactor.util.CertTools;

public abstract class AdminPreferenceSessionDefault {

    protected String makeAdminPreferenceId(final AuthenticationToken admin) {
        if (admin instanceof X509CertificateAuthenticationToken) {
            return CertTools.getFingerprintAsString(((X509CertificateAuthenticationToken) admin).getCertificate());
        } else if (admin instanceof PublicAccessAuthenticationToken) {
            return admin.getClass().getSimpleName();
        } else {
            return admin.getClass().getSimpleName() + ":" + admin.getPreferredMatchValue();
        }
    }
}

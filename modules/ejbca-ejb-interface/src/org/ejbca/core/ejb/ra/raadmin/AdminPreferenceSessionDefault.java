package org.ejbca.core.ejb.ra.raadmin;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.PublicAccessAuthenticationToken;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationToken;
import org.cesecore.util.CertTools;

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

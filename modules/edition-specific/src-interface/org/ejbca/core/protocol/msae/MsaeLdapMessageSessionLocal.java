package org.ejbca.core.protocol.msae;

import java.util.List;
import jakarta.ejb.Local;
import org.cesecore.config.MSAutoEnrollmentSettingsTemplate;


/**
 * Gets templates from LDAP service with local connection or over peers
 */
@Local
public interface MsaeLdapMessageSessionLocal {

    void testConnection(String domain, int port, String loginDN, String loginPassword, boolean useSSL, boolean followLdapReferral,
                        int ldapReadTimeout, int ldapConnectTimeout, String alias) throws LDAPException;

    List<MSAutoEnrollmentSettingsTemplate> getCertificateTemplateSettings(String alias);
}

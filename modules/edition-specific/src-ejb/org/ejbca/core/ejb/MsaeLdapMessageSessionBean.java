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
package org.ejbca.core.ejb;

import java.util.List;
import jakarta.ejb.Stateless;
import jakarta.ejb.TransactionAttribute;
import jakarta.ejb.TransactionAttributeType;
import org.cesecore.config.MSAutoEnrollmentSettingsTemplate;
import org.ejbca.core.protocol.msae.LDAPException;
import org.ejbca.core.protocol.msae.MsaeLdapMessageSessionLocal;

@Stateless
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class MsaeLdapMessageSessionBean implements MsaeLdapMessageSessionLocal {
    @Override
    public void testConnection(String domain, int port, String loginDN, String loginPassword, boolean useSSL, boolean followLdapReferral, int ldapReadTimeout, int ldapConnectTimeout, String alias) throws LDAPException {
        throw new UnsupportedOperationException("Msae is only supported in EJBCA Enterprise");
    }

    @Override
    public List<MSAutoEnrollmentSettingsTemplate> getCertificateTemplateSettings(String alias) {
        throw new UnsupportedOperationException("Msae is only supported in EJBCA Enterprise");
    }
}

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
package org.ejbca.core.model.ca.publisher.custpubl1;

import java.security.cert.Certificate;

import org.cesecore.certificates.endentity.ExtendedInformation;
import org.ejbca.core.model.ca.publisher.PublisherException;

import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPEntry;

/**
 * An additional mocked version of the CustomerLdapPublisher1 used by the unit
 * tests.
 *
 * @version @Id$
 */
public class SecondMockedCustomerLdapPublisher1 extends CustomerLdapPublisher1 {

    private boolean searchOldEntityCalled;
    private SearchOldEntityParameters searchOldEntityParameters;
    private PublisherException searchOldEntityException;
    private LDAPEntry searchOldEntityReturn;
    
    private boolean writeCertEntryToLDAPCalled;
    private WriteCertEntryToLDAPParameters writeCertEntryToLDAPParameters;
    private PublisherException writeCertEntryToLDAPException;    
    
    private boolean writeCrlEntryToLDAPCalled;
    private WriteCrlEntryToLDAPParameters writeCrlEntryToLDAPParameters;
    private PublisherException writeCrlEntryToLDAPException;

    
    // searchOldEntity
    @Override
    protected LDAPEntry searchOldEntity(LDAPConnection lc, String ldapDN) throws PublisherException {
        this.searchOldEntityCalled = true;
        this.searchOldEntityParameters = new SearchOldEntityParameters(lc, ldapDN);
        if (searchOldEntityException != null) {
            throw searchOldEntityException;
        }
        return searchOldEntityReturn;
    }

    public boolean isSearchOldEntityCalled() {
        return searchOldEntityCalled;
    }

    public SearchOldEntityParameters getSearchOldEntityParameters() {
        return searchOldEntityParameters;
    }

    public void setSearchOldEntityException(PublisherException searchOldEntityException) {
        this.searchOldEntityException = searchOldEntityException;
    }

    public void setSearchOldEntityReturn(LDAPEntry searchOldEntityReturn) {
        this.searchOldEntityReturn = searchOldEntityReturn;
    }

    
    // writeCertEntryToLDAP
    @Override
    protected void writeCertEntryToLDAP(LDAPConnection lc, LDAPEntry oldEntry, LDAPEntry newEntry, String certFingerprint) throws PublisherException {
        this.writeCertEntryToLDAPCalled = true;
        this.writeCertEntryToLDAPParameters = new WriteCertEntryToLDAPParameters(lc, oldEntry, newEntry, certFingerprint);
        if (this.writeCertEntryToLDAPException != null) {
            throw writeCertEntryToLDAPException;
        }
    }

    public boolean isWriteCertEntryToLDAPCalled() {
        return writeCertEntryToLDAPCalled;
    }

    public WriteCertEntryToLDAPParameters getWriteCertEntryToLDAPParameters() {
        return writeCertEntryToLDAPParameters;
    }

    public void setWriteCertEntryToLDAPException(PublisherException writeCertEntryToLDAPException) {
        this.writeCertEntryToLDAPException = writeCertEntryToLDAPException;
    }
    
    
    // writeCRLEntryToLDAP
    @Override
    protected void writeCrlEntryToLDAP(final LDAPConnection lc, final LDAPEntry oldEntry, final LDAPEntry newEntry) throws PublisherException {
        this.writeCrlEntryToLDAPCalled = true;
        this.writeCrlEntryToLDAPParameters = new WriteCrlEntryToLDAPParameters(lc, oldEntry, newEntry);
        if (this.writeCrlEntryToLDAPException != null) {
            throw writeCrlEntryToLDAPException;
        }
    }

    public boolean isWriteCrlEntryToLDAPCalled() {
        return writeCrlEntryToLDAPCalled;
    }

    public WriteCrlEntryToLDAPParameters getWriteCrlEntryToLDAPParameters() {
        return writeCrlEntryToLDAPParameters;
    }

    public void setWriteCrlEntryToLDAPException(PublisherException writeCrlEntryToLDAPException) {
        this.writeCrlEntryToLDAPException = writeCrlEntryToLDAPException;
    }
    
    
    public static class StoreLogParameters {
        private final String level;
        private final boolean success;
        private final String message;
        private final Exception exception;

        public StoreLogParameters(String level, boolean success, String message, Exception exception) {
            this.level = level;
            this.success = success;
            this.message = message;
            this.exception = exception;
        }

        public String getLevel() {
            return level;
        }

        public boolean isSuccess() {
            return success;
        }

        public String getMessage() {
            return message;
        }

        public Exception getException() {
            return exception;
        }
        
    }

    public static class DoStoreCertificateParameters {
        private final Certificate incert;
        private final String username;
        private final String password;
        private final String userDN; 
        private final ExtendedInformation extendedinformation;

        public DoStoreCertificateParameters(Certificate incert, String username, String password, String userDN, ExtendedInformation extendedinformation) {
            this.incert = incert;
            this.username = username;
            this.password = password;
            this.userDN = userDN;
            this.extendedinformation = extendedinformation;
        }

        public Certificate getIncert() {
            return incert;
        }

        public String getUsername() {
            return username;
        }

        public String getPassword() {
            return password;
        }

        public String getUserDN() {
            return userDN;
        }

        public ExtendedInformation getExtendedinformation() {
            return extendedinformation;
        }
    }
    
    public static class DoStoreCRLParameters {
        private final byte[] incrl;

        public DoStoreCRLParameters(byte[] incrl) {
            this.incrl = incrl;
        }

        public byte[] getIncrl() {
            return incrl;
        }
    }

    public static class SearchOldEntityParameters {
        private final LDAPConnection lc;
        private final String ldapDN;

        public SearchOldEntityParameters(LDAPConnection lc, String ldapDN) {
            this.lc = lc;
            this.ldapDN = ldapDN;
        }

        public LDAPConnection getLc() {
            return lc;
        }

        public String getLdapDN() {
            return ldapDN;
        }
        
    }

    public static class WriteCertEntryToLDAPParameters {
        private final LDAPConnection lc;
        private final LDAPEntry oldEntry;
        private final LDAPEntry newEntry;
        private final String certFingerprint;

        public WriteCertEntryToLDAPParameters(LDAPConnection lc, LDAPEntry oldEntry, LDAPEntry newEntry, String certFingerprint) {
            this.lc = lc;
            this.oldEntry = oldEntry;
            this.newEntry = newEntry;
            this.certFingerprint = certFingerprint;
        }

        public LDAPConnection getLc() {
            return lc;
        }

        public LDAPEntry getOldEntry() {
            return oldEntry;
        }

        public LDAPEntry getNewEntry() {
            return newEntry;
        }

        public String getCertFingerprint() {
            return certFingerprint;
        }
        
    }

    public static class WriteCrlEntryToLDAPParameters {
        private final LDAPConnection lc;
        private final LDAPEntry oldEntry;
        private final LDAPEntry newEntry;

        public WriteCrlEntryToLDAPParameters(LDAPConnection lc, LDAPEntry oldEntry, LDAPEntry newEntry) {
            this.lc = lc;
            this.oldEntry = oldEntry;
            this.newEntry = newEntry;
        }

        public LDAPConnection getLc() {
            return lc;
        }

        public LDAPEntry getOldEntry() {
            return oldEntry;
        }

        public LDAPEntry getNewEntry() {
            return newEntry;
        }
        
    }
    
}

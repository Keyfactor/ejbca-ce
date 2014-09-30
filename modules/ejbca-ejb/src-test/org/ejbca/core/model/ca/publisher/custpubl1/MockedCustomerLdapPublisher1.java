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

import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPEntry;
import java.security.cert.Certificate;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.ejbca.core.model.ca.publisher.PublisherConnectionException;
import org.ejbca.core.model.ca.publisher.PublisherException;

/**
 * Mocked version of the CustomerLdapPublisher1 used in the unit tests.
 *
 * @version @Id$
 */
public class MockedCustomerLdapPublisher1 extends CustomerLdapPublisher1 {

    private boolean doStoreCertificateCalled;
    private DoStoreCertificateParameters doStoreCertificateParameters;
    private PublisherException doStoreCertificateException;
    
    private boolean doStoreCRLCalled;
    private boolean doTestConnectionCalled;
    
    private StoreLogParameters storeLogParameters;
    private boolean storeLogCalled;
    private PublisherException storeLogException;
    private DoStoreCRLParameters doStoreCRLParameters;
    private PublisherException doStoreCRLException;
    private PublisherConnectionException doTestConnectionException;
    
    private SearchOldEntityParameters searchOldEntityParameters;
    private PublisherException searchOldEntityException;
    private LDAPEntry searchOldEntityReturn;
    
    
    // doStoreCertificate
    @Override
    protected boolean doStoreCertificate(Certificate incert, String username, String password, String userDN, ExtendedInformation extendedinformation) throws PublisherException {
        doStoreCertificateCalled = true;
        doStoreCertificateParameters = new DoStoreCertificateParameters(incert, username, password, userDN, extendedinformation);
        
        if (doStoreCertificateException != null) {
            throw doStoreCertificateException;
        }
        
        return true;
    }

    public void setDoStoreCertificateException(PublisherException doStoreCertificateException) {
        this.doStoreCertificateException = doStoreCertificateException;
    }

    public DoStoreCertificateParameters getDoStoreCertificateParameters() {
        return doStoreCertificateParameters;
    }

    public boolean isDoStoreCertificateCalled() {
        return doStoreCertificateCalled;
    }

    
    // storeLog
    @Override
    protected void storeLog(String level, boolean success, String message, Exception exception) throws PublisherException {
        storeLogParameters = new StoreLogParameters(level, success, message, exception);
        storeLogCalled = true;
        
        if (storeLogException != null) {
            throw storeLogException;
        }
    }

    public StoreLogParameters getStoreLogParameters() {
        return storeLogParameters;
    }

    public boolean isStoreLogCalled() {
        return storeLogCalled;
    }

    public void setStoreLogException(PublisherException publisherException) {
        this.storeLogException = publisherException;
    }
    
    
    // doStoreCRL
    @Override
    protected void doStoreCRL(byte[] incrl) throws PublisherException {
        doStoreCRLCalled = true;
        this.doStoreCRLParameters = new DoStoreCRLParameters(incrl);
        if (doStoreCRLException != null) {
            throw doStoreCRLException;
        }
    }

    public boolean isDoStoreCRLCalled() {
        return doStoreCRLCalled;
    }

    public DoStoreCRLParameters getDoStoreCRLParameters() {
        return doStoreCRLParameters;
    }

    public void setDoStoreCRLException(PublisherException publisherException) {
        this.doStoreCRLException = publisherException;
    }
    
    
    // doTestConnection
    @Override
    protected void doTestConnection() throws PublisherConnectionException {
        this.doTestConnectionCalled = true;
        if (doTestConnectionException != null) {
            throw doTestConnectionException;
        }
    }

    public void setDoTestConnectionException(PublisherConnectionException doTestConnectionException) {
        this.doTestConnectionException = doTestConnectionException;
    }

    public boolean isDoTestConnectionCalled() {
        return doTestConnectionCalled;
    }

    
    // searchOldEntity
    @Override
    protected LDAPEntry searchOldEntity(LDAPConnection lc, String ldapDN) throws PublisherException {
        this.searchOldEntityParameters = new SearchOldEntityParameters(lc, ldapDN);
        if (searchOldEntityException != null) {
            throw searchOldEntityException;
        }
        return searchOldEntityReturn;
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
    
}

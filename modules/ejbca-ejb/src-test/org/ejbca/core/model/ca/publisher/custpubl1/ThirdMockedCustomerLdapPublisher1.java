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

import org.ejbca.core.model.ca.publisher.PublisherException;

import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;

/**
 * An additional mocked version of the CustomerLdapPublisher1 used by the unit
 * tests.
 *
 * @version $Id$
 */
public class ThirdMockedCustomerLdapPublisher1 extends CustomerLdapPublisher1 {

    private boolean writeLogEntryToLDAPCalled;
    private List<WriteLogEntryToLDAPParameters> writeLogEntryToLDAPParameters = new ArrayList<WriteLogEntryToLDAPParameters>();
    
    private HashSet<String> storedDNs = new HashSet<String>();
    
    private long time;

    public long getTime() {
        return time;
    }

    public void setTime(long time) {
        this.time = time;
    }

    @Override
    protected Date getCurrentTime() {
        return new Date(time);
    }
    
    
    // writeLogEntryToLDAP
    @Override
    protected void writeLogEntryToLDAP(final LDAPConnection lc, final LDAPEntry newEntry) throws PublisherException {
        this.writeLogEntryToLDAPCalled = true;
        this.writeLogEntryToLDAPParameters.add(new WriteLogEntryToLDAPParameters(lc, newEntry));
        if (!storedDNs.add(newEntry.getDN())) {
            final LDAPException ldapEx = new LDAPException("Entry Exists", LDAPException.ENTRY_ALREADY_EXISTS, "entryAlreadyExists");
            final PublisherException pex = new PublisherException("Entry already exists");
            pex.initCause(ldapEx);
            throw pex;
        }
    }

    public boolean isWriteLogEntryToLDAPCalled() {
        return writeLogEntryToLDAPCalled;
    }

    public List<WriteLogEntryToLDAPParameters> getWriteCertEntryToLDAPParameters() {
        return writeLogEntryToLDAPParameters;
    }
    
    public void clearWriteCertEntryToLDAPParameters() {
        writeLogEntryToLDAPParameters.clear();
    }


    public static class WriteLogEntryToLDAPParameters {
        private final LDAPConnection lc;
        private final LDAPEntry newEntry;

        public WriteLogEntryToLDAPParameters(final LDAPConnection lc, final LDAPEntry newEntry) {
            this.lc = lc;
            this.newEntry = newEntry;
        }

        public LDAPConnection getLc() {
            return lc;
        }

        public LDAPEntry getNewEntry() {
            return newEntry;
        }
        
    }
    
}

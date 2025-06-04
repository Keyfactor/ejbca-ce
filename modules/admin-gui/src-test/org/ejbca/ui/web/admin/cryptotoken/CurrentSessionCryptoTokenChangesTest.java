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
package org.ejbca.ui.web.admin.cryptotoken;

import org.cesecore.keys.token.CryptoTokenSessionLocal;
import org.easymock.EasyMock;
import org.junit.Test;

public class CurrentSessionCryptoTokenChangesTest {

    @Test
    public void localStateChangesNeverRequireUpdates() {
        // this always runs on the same JVM, so session state and jvm state shouldn't vary
        CryptoTokenSessionLocal cryptoTokenSessionLocal = EasyMock.createMock(CryptoTokenSessionLocal.class);
        // no expect() calls, so we expect no interaction with cryptoTokenSessionLocal
        EasyMock.replay(cryptoTokenSessionLocal);
        
        var currentSessionCryptoTokenChanges = new CurrentSessionCryptoTokenChanges();
        currentSessionCryptoTokenChanges.tokenChanged(1);
        currentSessionCryptoTokenChanges.tokenChanged(2);
        currentSessionCryptoTokenChanges.tokenChanged(3);
        currentSessionCryptoTokenChanges.tokenChanged(1);
        currentSessionCryptoTokenChanges.tokenChanged(2);
        currentSessionCryptoTokenChanges.tokenChanged(3);
        currentSessionCryptoTokenChanges.refreshChangedCryptoTokens(cryptoTokenSessionLocal);
        
        EasyMock.verify(cryptoTokenSessionLocal);
    }

    @Test
    public void jvmStateChangesCausesUpdate() {
        // simulate a different JVM and confirm that it causes updates
        CryptoTokenSessionLocal cryptoTokenSessionLocal = EasyMock.createMock(CryptoTokenSessionLocal.class);
        
        cryptoTokenSessionLocal.flushId(EasyMock.anyInt());
        EasyMock.expectLastCall().times(1);
        EasyMock.replay(cryptoTokenSessionLocal);
        
        var currentSessionCryptoTokenChanges = new CurrentSessionCryptoTokenChanges();
        currentSessionCryptoTokenChanges.tokenChanged(1);
        currentSessionCryptoTokenChanges.tokenChanged(2);
        currentSessionCryptoTokenChanges.tokenChanged(3);
        currentSessionCryptoTokenChanges.tokenChanged(1);
        currentSessionCryptoTokenChanges.tokenChanged(2);
        currentSessionCryptoTokenChanges.tokenChanged(3);
        currentSessionCryptoTokenChanges.changeOneJvmState();
        currentSessionCryptoTokenChanges.refreshChangedCryptoTokens(cryptoTokenSessionLocal);
        
        EasyMock.verify(cryptoTokenSessionLocal);
    }

}

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
package org.cesecore.certificates.certificate;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.apache.log4j.Logger;
import org.cesecore.jndi.JndiConstants;

/**
 * @version $Id$
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "UniqueSernoHelperTestSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class UniqueSernoHelperTestSessionBean implements UniqueSernoHelperTestSessionRemote {

    private static final Logger log = Logger.getLogger(UniqueSernoHelperTestSessionBean.class);

    @EJB 
    CertificateStoreSessionLocal certificateStoreSession;
    
    @Override
    public void setUniqueSernoOkIndex() {
        log.info("Setting unique serno check to OK, i.e. force EJBCA to believe we have a unique issuerDN/SerialNo index in the database");
        final Class<?>[] cs = {CertificateStoreSession.class};
        final InvocationHandler certificateStoreSessionProxy = new CertificateStoreSessionMock(null, null, true, new Exception());
        final CertificateStoreSession certificateStoreSessionMock = (CertificateStoreSession) Proxy.newProxyInstance(CertificateStoreSession.class.getClassLoader(), cs, certificateStoreSessionProxy);
        UniqueSernoHelper.reset();
        UniqueSernoHelper.isUniqueCertificateSerialNumberIndex(certificateStoreSessionMock);
    }
    
    public boolean existsUniqueSernoIndex() {
        UniqueSernoHelper.reset();        
        return UniqueSernoHelper.isUniqueCertificateSerialNumberIndex(certificateStoreSession);
    }

    @Override
    public void resetUniqueSernoCheck() {
        log.info("Resetting unique serno check");
        UniqueSernoHelper.reset();        
    }
    
    /** Proxy class that mocks two consecutive interactions with CertificateStoreSession for find and store. */
    private class CertificateStoreSessionMock implements InvocationHandler {
        // Methods that we proxy to avoid having to care about when other methods change signature
        private static final String MOCKED_METHOD_FINDCERT = "findCertificateByFingerprint";
        private static final String MOCKED_METHOD_STORECERT = "storeCertificate";

        final Object findResult1;
        final Object findResult2;
        final Object storeResult1;
        final Object storeResult2;

        boolean firstFind = true;
        boolean firstStore = true;

        public CertificateStoreSessionMock(final Object findResult1, final Object findResult2, final Object storeResult1, final Object storeResult2) {
            this.findResult1 = findResult1;
            this.findResult2 = findResult2;
            this.storeResult1 = storeResult1;
            this.storeResult2 = storeResult2;
            // Verify that this proxy is valid, since we use method names as String objects.. (might have changed)
            boolean findPresent = false; 
            boolean storePresent = false; 
            for (final Method m : CertificateStoreSession.class.getDeclaredMethods()) {
                if (MOCKED_METHOD_FINDCERT.equals(m.getName())) {
                    findPresent = true;
                } else if (MOCKED_METHOD_STORECERT.equals(m.getName())) {
                    storePresent = true;
                }
            }
            if (!findPresent || !storePresent) {
                throw new RuntimeException("This test is no longer valid due to code changes.");
            }
        }
        
        @Override
        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
            final String methodName = method.getName();
            log.debug("proxy method invoked: " + methodName);
            Object result = null;
            if (MOCKED_METHOD_FINDCERT.equals(methodName)) {
                if (firstFind) {
                    firstFind = false;
                    result = findResult1;
                } else {
                    result = findResult2;
                }
            } else if (MOCKED_METHOD_STORECERT.equals(methodName)) {
                if (firstStore) {
                    firstStore = false;
                    result = storeResult1;
                } else {
                    result = storeResult2;
                }
            }
            if (result != null && result instanceof Throwable) {
                throw (Throwable) result;
            }
            return result;
        }
    }

}

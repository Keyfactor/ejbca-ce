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
package org.cesecore.junit.util;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.keys.token.CryptoTokenAuthenticationFailedException;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.CryptoTokenNameInUseException;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.p11.exception.NoSuchSlotException;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.junit.Test;
import org.junit.internal.AssumptionViolatedException;
import org.junit.internal.runners.model.EachTestNotifier;
import org.junit.runner.notification.RunNotifier;
import org.junit.runner.notification.StoppedByUserException;
import org.junit.runners.BlockJUnit4ClassRunner;
import org.junit.runners.model.FrameworkMethod;
import org.junit.runners.model.InitializationError;
import org.junit.runners.model.Statement;


/**
 * Base class for crypto token variations of the test runner. 
 * 
 * @version $Id$
 *
 */
public abstract class CryptoTokenRunner extends BlockJUnit4ClassRunner {

    private static final Logger log = Logger.getLogger(CryptoTokenTestRunner.class);
    
    private final CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CryptoTokenManagementSessionRemote.class);

    protected Map<Integer, CA> casToRemove = new HashMap<Integer, CA>();
    protected int cryptoTokenId;

    private final AuthenticationToken alwaysAllowToken = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal(
            CryptoTokenRunner.class.getSimpleName()));

    public CryptoTokenRunner(Class<?> klass) throws InitializationError, NoSuchMethodException, SecurityException {
        super(klass);
        CryptoProviderTools.installBCProviderIfNotAvailable();
        CryptoTokenRule.setCallback(this);
    }
    
    public void tearDownAllCas() {
        List<CA> defensiveCopy = new ArrayList<CA>(casToRemove.values());
        for(CA ca : defensiveCopy) {
            tearDownCa(ca);
        }
    }

    @Override
    protected List<FrameworkMethod> computeTestMethods() {
        final List<FrameworkMethod> allMethods = getTestClass().getAnnotatedMethods(Test.class);
        if (allMethods == null || allMethods.size() == 0) {
            return allMethods;
        }
        final List<FrameworkMethod> filteredMethods = new ArrayList<FrameworkMethod>(allMethods.size());
        for (final FrameworkMethod method : allMethods) {
            final RunOnly runOnly = method.getAnnotation(RunOnly.class);
           
            if (runOnly != null) {
                log.info("Found test method with RunOnly implementation: " + method.getName() + ", subtype is " + getSubtype() + ", expecting " + runOnly.implementation());
                if (getSubtype().equalsIgnoreCase(runOnly.implementation())) {
                    filteredMethods.add(method);
                }
            } else {
                // Default behavior is to always run
                filteredMethods.add(method);
            }
        }
        return filteredMethods;
    }

    public void teardownCryptoToken() {
        try {
            cryptoTokenManagementSession.deleteCryptoToken(alwaysAllowToken, cryptoTokenId);
        } catch (AuthorizationDeniedException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public void run(final RunNotifier notifier) {
        EachTestNotifier testNotifier = new EachTestNotifier(notifier, getDescription());
        try {
            Statement statement = classBlock(notifier);
            statement.evaluate();
        } catch (AssumptionViolatedException e) {
            testNotifier.fireTestIgnored();
        } catch (StoppedByUserException e) {
            throw e;
        } catch (Throwable e) {
            testNotifier.addFailure(e);
        }
    }

    
    protected String getSubjectDn() {
        return "SN=1234, CN=" + getSimpleName() + getSubtype();
    }
    
    protected String getSimpleName() {
        return getTestClass().getJavaClass().getSimpleName();
    }
    
    @Override
    // The name of the test class  
    protected String getName() {
        return String.format("%s [%s]", super.getName(), getSubtype());
    }

    @Override
    // The name of the test method  
    protected String testName(final FrameworkMethod method) {
        return String.format("%s [%s]", method.getName(), getSubtype());
    }
    
    public abstract X509CA createX509Ca() throws Exception;

    public abstract void tearDownCa(CA ca);

    /**
     * @return a string differentiatior for the class inheriting this baseclass, mostly used for naming reasons. 
     */
    public abstract String getSubtype();
    
    /**
     * Will create a crypto token, as defined by the implementing subclass. 
     * 
     * @return the crypto token ID, never null.
     * @throws NoSuchSlotException if the defined slot could not be found
     * @throws CryptoTokenNameInUseException if a crypto token with the predefined name already exists
     * @throws CryptoTokenAuthenticationFailedException if the crypto token could not be authenticated against
     * @throws CryptoTokenOfflineException if the crypto token could not be activated
     */
    public abstract Integer createCryptoToken() throws CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException,
            CryptoTokenNameInUseException, NoSuchSlotException;

}

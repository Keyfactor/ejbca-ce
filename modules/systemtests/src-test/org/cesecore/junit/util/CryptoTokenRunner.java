/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
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

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
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

    protected final static String CA_CREATION_METHOD_NAME = "createX509Ca";
    protected final static String CA_TEARDOWN_METHOD_NAME = "tearDownX509Ca";
    protected final static String CRYPTOTOKEN_CREATION_METHOD_NAME = "createCryptoToken";
    protected final static String CRYPTOTOKEN_TEARDOWN_METHOD_NAME = "teardownCryptoToken";

    private final CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CryptoTokenManagementSessionRemote.class);
    
    protected X509CA x509ca;
    protected int cryptoTokenId;

    private final AuthenticationToken alwaysAllowToken = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal(
            CryptoTokenRunner.class.getSimpleName()));

    
    public CryptoTokenRunner(Class<?> klass) throws InitializationError, NoSuchMethodException, SecurityException {
        super(klass);
        CryptoProviderTools.installBCProviderIfNotAvailable();
        CryptoTokenRule.setCreationMethod(this, this.getClass().getMethod(CA_CREATION_METHOD_NAME), this.getClass()
                .getMethod(CA_TEARDOWN_METHOD_NAME), this.getClass().getMethod(CRYPTOTOKEN_CREATION_METHOD_NAME),
                this.getClass().getMethod(CRYPTOTOKEN_TEARDOWN_METHOD_NAME));
    }

    public abstract X509CA createX509Ca() throws Exception;

    public abstract void tearDownX509Ca() throws Exception;

    public abstract Integer createCryptoToken() throws Exception;

    public void teardownCryptoToken() throws AuthorizationDeniedException {
        cryptoTokenManagementSession.deleteCryptoToken(alwaysAllowToken, cryptoTokenId);
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

    public abstract String getSubtype();

}

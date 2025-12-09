package org.jscep.client.inspect;

import java.io.IOException;
import java.security.cert.CertStore;
import java.security.cert.X509CertSelector;
import java.util.Arrays;
import java.util.Collection;

/**
 * Implementation of the <code>CertStoreInspector</code> for Apache Harmony (Android)
 */
final class HarmonyCertStoreInspector extends AbstractCertStoreInspector {
    /**
     * @param store
     *            the store to inspect
     */
    HarmonyCertStoreInspector(final CertStore store) {
        super(store);
    }

    /**
     * {@inheritDoc}
     */
    @Override
	protected Collection<X509CertSelector> getIssuerSelectors(byte[] subjectDN) {
		X509CertSelector caSelector = new X509CertSelector();
        caSelector.setBasicConstraints(0);
        try {
            caSelector.setSubject(subjectDN);
        } catch (IOException e) {
            // shut up
        }
        
		return Arrays.asList(caSelector);
	}

	/**
     * {@inheritDoc}
     */
    @Override
	protected Collection<X509CertSelector> getSignerSelectors() {
        X509CertSelector digSigSelector = new X509CertSelector();
        digSigSelector.setBasicConstraints(-2);
        digSigSelector.setKeyUsage(new boolean[] {true});
        
        X509CertSelector caSelector = new X509CertSelector();
        caSelector.setBasicConstraints(0);
        
		return Arrays.asList(digSigSelector, caSelector);
	}

	/**
     * {@inheritDoc}
     */
    @Override
	protected Collection<X509CertSelector> getRecipientSelectors() {
        X509CertSelector keyEncSelector = new X509CertSelector();
        keyEncSelector.setKeyUsage(new boolean[] {false, false, true});
        
        X509CertSelector dataEncSelector = new X509CertSelector();
        dataEncSelector.setKeyUsage(new boolean[] {false, false, false, true});
        
        X509CertSelector caSelector = new X509CertSelector();
        caSelector.setBasicConstraints(0);
        
		return Arrays.asList(keyEncSelector, dataEncSelector, caSelector);
	}
}


package org.jscep.client.inspect;

import java.io.IOException;
import java.security.cert.CertStore;
import java.security.cert.X509CertSelector;
import java.util.Arrays;
import java.util.Collection;

/**
 * Default implementation of the <code>CertStoreInspector</code>
 */
final class DefaultCertStoreInspector extends AbstractCertStoreInspector {
	/**
	 * @param store
	 *            the store to inspect
	 */
	DefaultCertStoreInspector(final CertStore store) {
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
            		// Do nothing
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
		digSigSelector.setKeyUsage(new boolean[] { true });

		X509CertSelector caSelector = new X509CertSelector();
		caSelector.setBasicConstraints(0);

		return Arrays.asList(digSigSelector, caSelector);
	}

	/**
     	 * {@inheritDoc}
     	 */
	protected Collection<X509CertSelector> getRecipientSelectors() {
		boolean digitalSignature = false;
		boolean nonRepudiation = false;
		boolean keyEncipherment = true;
		boolean dataEncipherment = false;
		
		X509CertSelector keyEncSelector = new X509CertSelector();
		keyEncSelector.setBasicConstraints(-2);
		keyEncSelector.setKeyUsage(new boolean[] {
			digitalSignature, 
			nonRepudiation, 
			keyEncipherment,
			dataEncipherment
		});
		keyEncSelector.setBasicConstraints(-1); //NOTE: Set by the EJBCA team, otherwise CA certs are not allowed to be generally used. 

		keyEncipherment = false;
		dataEncipherment = true;

		X509CertSelector dataEncSelector = new X509CertSelector();
		dataEncSelector.setBasicConstraints(-2);
		dataEncSelector.setKeyUsage(new boolean[] {
			digitalSignature, 
			nonRepudiation, 
			keyEncipherment, 
			dataEncipherment
		});

		X509CertSelector caSelector = new X509CertSelector();
		caSelector.setBasicConstraints(0);

		return Arrays.asList(keyEncSelector, dataEncSelector, caSelector);
	}
}


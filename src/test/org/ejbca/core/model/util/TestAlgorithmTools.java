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

package org.ejbca.core.model.util;

import java.math.BigInteger;
import java.security.PublicKey;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Collection;
import java.util.Iterator;

import junit.framework.TestCase;

import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jce.provider.JCEECPublicKey;

/**
 * Tests for AlgorithmTools.
 * Mostly tests border cases.
 * 
 * @version $Id$
 */
public class TestAlgorithmTools extends TestCase {

	public void testGetKeyAlgorithm() {
		assertNull("null if no match", AlgorithmTools.getKeyAlgorithm(new MockNotSupportedPublicKey()));
	}

	public void testGetSignatureAlgorithms() {
		Collection algs = AlgorithmTools.getSignatureAlgorithms(new MockNotSupportedPublicKey()); 
		assertNotNull("should not return null", algs);
		assertTrue("no supported algs", algs.isEmpty());
	}

	public void testGetKeyAlgorithmFromSigAlg() {
		
		Collection sigAlgs;
		
		// Test that key algorithm is RSA for all of its signature algorithms
		sigAlgs = AlgorithmTools.getSignatureAlgorithms(new MockRSAPublicKey());
		for(Iterator i = sigAlgs.iterator(); i.hasNext();) {
			assertEquals(AlgorithmTools.getKeyAlgorithm(new MockRSAPublicKey()), AlgorithmTools.getKeyAlgorithmFromSigAlg((String)i.next()));
		}
		
		// Test that key algorithm is DSA for all of its signature algorithms
		sigAlgs = AlgorithmTools.getSignatureAlgorithms(new MockDSAPublicKey());
		for(Iterator i = sigAlgs.iterator(); i.hasNext();) {
			assertEquals(AlgorithmTools.getKeyAlgorithm(new MockDSAPublicKey()), AlgorithmTools.getKeyAlgorithmFromSigAlg((String)i.next()));
		}
		
		// Test that key algorithm is ECDSA for all of its signature algorithms
		sigAlgs = AlgorithmTools.getSignatureAlgorithms(new MockDSAPublicKey());
		for(Iterator i = sigAlgs.iterator(); i.hasNext();) {
			assertEquals(AlgorithmTools.getKeyAlgorithm(new MockDSAPublicKey()), AlgorithmTools.getKeyAlgorithmFromSigAlg((String)i.next()));
		}
		
		// should return a default value
		assertNotNull("should return a default value", AlgorithmTools.getKeyAlgorithmFromSigAlg("_NonExistingAlg"));
		
	}

	public void testGetKeySpecification() {
		assertNull("null if the key algorithm is not supported", AlgorithmTools.getKeySpecification(new MockNotSupportedPublicKey()));
		assertEquals("unknown", AlgorithmTools.getKeySpecification(new MockECDSAPublicKey()));
	}

	public void testGetEncSigAlgFromSigAlg() {
	}

	public void testIsCompatibleSigAlg() {
	}
	
	private static class MockPublicKey implements PublicKey {
		@Override public String getAlgorithm() { return null; }
		@Override public byte[] getEncoded() { return null; }
		@Override public String getFormat() { return null; }		
	}
	
	private static class MockNotSupportedPublicKey extends MockPublicKey {}
	
	private static class MockRSAPublicKey extends MockPublicKey implements RSAPublicKey {
		@Override public BigInteger getPublicExponent() { return null; }
		@Override public BigInteger getModulus() { return null; }
	}
	
	private static class MockDSAPublicKey extends MockPublicKey implements DSAPublicKey {
		@Override public BigInteger getY() { return null; }
		@Override public DSAParams getParams() { return null; }
	}
	
	private static class MockECDSAPublicKey extends JCEECPublicKey {
		public MockECDSAPublicKey() {
			super("ECDSA", new ECPublicKeyParameters(null, null));
		}
	}

}

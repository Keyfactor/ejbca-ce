/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.certificates.util;

import java.math.BigInteger;
import java.security.PublicKey;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;


/**
 * Classes used by TestAlgorithmTools.
 * 
 * @version $Id$
 */
public class AlgorithmToolsHelper {
	
	static class MockPublicKey implements PublicKey {
		private static final long serialVersionUID = 1L;
		public String getAlgorithm() { return null; }
		public byte[] getEncoded() { return null; }
		public String getFormat() { return null; }		
	}
	
	static class MockNotSupportedPublicKey extends MockPublicKey {
		private static final long serialVersionUID = 1L;
	}
	
	static class MockRSAPublicKey extends MockPublicKey implements RSAPublicKey {
		private static final long serialVersionUID = 1L;
		public BigInteger getPublicExponent() { return BigInteger.valueOf(1); }
		public BigInteger getModulus() { return BigInteger.valueOf(1000); }
	}
	
	static class MockDSAPublicKey extends MockPublicKey implements DSAPublicKey {
		private static final long serialVersionUID = 1L;
		public BigInteger getY() { return BigInteger.valueOf(1); }
		public DSAParams getParams() { return null; }
	}
	
	static class MockECDSAPublicKey extends MockPublicKey implements ECPublicKey {
		private static final long serialVersionUID = 1L;
		public ECPoint getW() { return null; }
		public ECParameterSpec getParams() { return null; }
		@Override
		public String getAlgorithm() {
		    return "ECDSA mock";
		}
	}
	
	static class MockGOST3410PublicKey extends MockPublicKey implements ECPublicKey {
        private static final long serialVersionUID = 1L;
        public ECPoint getW() { return null; }
        public ECParameterSpec getParams() { return null; }
        @Override
        public String getAlgorithm() {
            return "GOST mock";
        }
    }
	
	static class MockDSTU4145PublicKey extends MockPublicKey implements ECPublicKey {
        private static final long serialVersionUID = 1L;
        public ECPoint getW() { return null; }
        public ECParameterSpec getParams() { return null; }
        @Override
        public String getAlgorithm() {
            return "DSTU mock";
        }
    }
}

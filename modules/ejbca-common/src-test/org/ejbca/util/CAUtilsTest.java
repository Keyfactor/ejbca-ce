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
package org.ejbca.util;

import org.cesecore.certificates.ca.X509CA;
import org.junit.Test;

import static org.easymock.EasyMock.createMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Unit test for {@link CAUtils}.
 */
public class CAUtilsTest {

	@Test
	public void shouldDoPreProduceOcspResponses() {
		//given
		X509CA ca = createMock(X509CA.class);
		expect(ca.isDoPreProduceOcspResponses()).andReturn(true);
		replay(ca);

		//when
		boolean produceOcspResponse = CAUtils.isDoPreProduceOcspResponses(ca);

		//then
		assertTrue(produceOcspResponse);
	}

	@Test
	public void shouldNotPreProduceOcspResponses() {
		//given
		X509CA ca = createMock(X509CA.class);
		expect(ca.isDoPreProduceOcspResponses()).andReturn(false);
		replay(ca);

		//when
		boolean produceOcspResponse = CAUtils.isDoPreProduceOcspResponses(ca);

		//then
		assertFalse(produceOcspResponse);
	}

}

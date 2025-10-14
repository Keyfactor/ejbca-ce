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
package org.ejbca.core.protocol.scep;

import jakarta.ejb.TimerService;
import jakarta.transaction.SystemException;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.easymock.EasyMock;
import org.ejbca.config.AvailableProtocolsConfiguration;
import org.junit.Test;

import java.util.ArrayList;

import static org.easymock.EasyMock.anyObject;
import static org.easymock.EasyMock.anyString;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.expectLastCall;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.ejbca.util.SimpleMock.inject;

public class ScepKeyRenewalSessionBeanUnitTest {

	@Test
	public void testKeyRenewalSuccess() throws SystemException {
		final var scepKeyRenewalSessionBean = new ScepKeyRenewalSessionBean();
		final ScepKeyRenewalDataSessionLocal scepKeyRenewalDataSessionLocalMock = EasyMock.createMock(
				ScepKeyRenewalDataSessionLocal.class);
		scepKeyRenewalDataSessionLocalMock.renewScepKeys();
		expectLastCall().once();
		replay(scepKeyRenewalDataSessionLocalMock);
		inject(scepKeyRenewalSessionBean, "scepKeyRenewalDataSession", scepKeyRenewalDataSessionLocalMock);

		scepKeyRenewalSessionBean.timeoutHandler(null);

		verify(scepKeyRenewalDataSessionLocalMock);
	}

	@Test
	public void testStartSuccess() {
		final var scepKeyRenewalSessionBean = new ScepKeyRenewalSessionBean();
		final GlobalConfigurationSessionLocal globalConfigSessionMock = EasyMock.createMock(
				GlobalConfigurationSessionLocal.class);
		final TimerService timerServiceMock = EasyMock.createMock(TimerService.class);
		final AvailableProtocolsConfiguration availableProtocolsConfiguration = new AvailableProtocolsConfiguration();
		availableProtocolsConfiguration.setProtocolStatus("SCEP", true);
		expect(globalConfigSessionMock.getCachedConfiguration(anyString())).andReturn(availableProtocolsConfiguration);
		expect(timerServiceMock.getTimers()).andReturn(new ArrayList<>());
		expect(timerServiceMock.createCalendarTimer(anyObject(), anyObject())).andReturn(null);
		replay(globalConfigSessionMock, timerServiceMock);
		inject(scepKeyRenewalSessionBean, "globalConfigSession", globalConfigSessionMock);
		inject(scepKeyRenewalSessionBean, "timerService", timerServiceMock);

		scepKeyRenewalSessionBean.start();

		verify(globalConfigSessionMock);
	}

	@Test
	public void testNotStartSuccess() {
		final var scepKeyRenewalSessionBean = new ScepKeyRenewalSessionBean();
		final GlobalConfigurationSessionLocal globalConfigSessionMock = EasyMock.createMock(
				GlobalConfigurationSessionLocal.class);
		final AvailableProtocolsConfiguration availableProtocolsConfiguration = new AvailableProtocolsConfiguration();
		availableProtocolsConfiguration.setProtocolStatus("SCEP", false);
		expect(globalConfigSessionMock.getCachedConfiguration(anyString())).andReturn(availableProtocolsConfiguration);
		replay(globalConfigSessionMock);
		inject(scepKeyRenewalSessionBean, "globalConfigSession", globalConfigSessionMock);

		scepKeyRenewalSessionBean.start();

		verify(globalConfigSessionMock);
	}

}

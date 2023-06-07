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
package org.ejbca.core.ejb.ra;

import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.easymock.EasyMockRunner;
import org.easymock.Mock;
import org.easymock.TestSubject;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionBean.UserDataQueryResult;
import org.ejbca.util.query.IllegalQueryException;
import org.ejbca.util.query.Query;
import org.junit.Test;
import org.junit.runner.RunWith;

import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertTrue;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;

@RunWith(EasyMockRunner.class)
public class EndEntityAccessSessionBeanTest {

	@Mock
	private GlobalConfigurationSessionLocal globalConfigurationSession;

	@TestSubject
	private EndEntityAccessSessionBean endEntityAccessSession = new EndEntityAccessSessionBean();

	@Test
	public void shouldConstructUserDataQuery() throws IllegalQueryException {
		//given
		final Query query = new Query(1);
		query.add(2, 0, "40");
		final String caAuthorization = "(  cAId = 618042534 OR cAId = -406472569 OR cAId = 240275169 "
				+ "OR cAId = 1063845197 OR cAId = 498780802 OR cAId = -893925638 OR cAId = 1652389506 )";
		final String endEntityProfile = "(  endEntityProfileId = 1 OR endEntityProfileId = 1908729756 "
				+ "OR endEntityProfileId = 341377459 OR endEntityProfileId = 565046902 "
				+ "OR endEntityProfileId = 593825433 OR endEntityProfileId = 344292554 "
				+ "OR endEntityProfileId = 1746014445 )";
		final AuthenticationToken admin = new AlwaysAllowLocalAuthenticationToken(
				new UsernamePrincipal("EndEntityAccessSessionBeanTestAT"));
		final String endEntityAccessRule = "/view_end_entity";
		final boolean authorizedToAnyProfile = true;

		GlobalConfiguration globalConfiguration = new GlobalConfiguration();
		globalConfiguration.setEnableEndEntityProfileLimitations(true);
		expect(globalConfigurationSession.getCachedConfiguration(
				GlobalConfiguration.GLOBAL_CONFIGURATION_ID)).andReturn(globalConfiguration);
		replay(globalConfigurationSession);

		//when
		UserDataQueryResult result = endEntityAccessSession.constructUserDataQuery(query, caAuthorization,
				endEntityProfile, admin, endEntityAccessRule, authorizedToAnyProfile);

		//then
		assertEquals("((status = 40) AND (  cAId = 618042534 OR cAId = -406472569 "
				+ "OR cAId = 240275169 OR cAId = 1063845197 OR cAId = 498780802 "
				+ "OR cAId = -893925638 OR cAId = 1652389506 )) AND "
				+ "(  endEntityProfileId = 1 OR endEntityProfileId = 1908729756 "
				+ "OR endEntityProfileId = 341377459 OR endEntityProfileId = 565046902 "
				+ "OR endEntityProfileId = 593825433 OR endEntityProfileId = 344292554 "
				+ "OR endEntityProfileId = 1746014445 ) ORDER BY timeCreated DESC", result.getWhereValue());
		assertTrue(result.isAuthorizedToAnyProfile());
	}

}

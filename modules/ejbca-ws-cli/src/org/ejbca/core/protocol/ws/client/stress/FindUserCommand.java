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

package org.ejbca.core.protocol.ws.client.stress;

import org.ejbca.core.protocol.ws.client.gen.EjbcaWS;
import org.ejbca.core.protocol.ws.client.gen.UserDataVOWS;
import org.ejbca.core.protocol.ws.client.gen.UserMatch;
import org.ejbca.util.PerformanceTest;
import org.ejbca.util.query.BasicMatch;

import java.util.Iterator;
import java.util.List;

public class FindUserCommand extends BaseCommand implements PerformanceTest.Command {
    public FindUserCommand(EjbcaWS ejbcaWS, JobData jobData, PerformanceTest.Log log) {
        super(ejbcaWS, jobData, log);
    }

    @Override
    public boolean doIt() throws Exception {
        final UserMatch match = new UserMatch();
        match.setMatchtype(BasicMatch.MATCH_TYPE_EQUALS);
        match.setMatchvalue(this.jobData.getDN());
        match.setMatchwith(org.ejbca.util.query.UserMatch.MATCH_WITH_DN);
        final List<UserDataVOWS> result = this.ejbcaWS.findUser(match);
        if (result.size()<1) {
            log.error("No users found for DN \""+this.jobData.getDN()+"\"");
            return false;
        }
        final Iterator<UserDataVOWS> i = result.iterator();
        while ( i.hasNext() ) {
            final String userName = i.next().getUsername();
            if( !userName.equals(this.jobData.userName) ) {
                log.error("wrong user name \""+userName+"\" for certificate with DN \""+this.jobData.getDN()+"\"");
                return false;
            }
        }
        return true;
    }

    @Override
    public String getJobTimeDescription() {
        return "";
    }
}

package org.ejbca.ui.cli.service;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.services.ServiceSessionRemote;
import org.ejbca.ui.cli.ErrorAdminCommandException;

class ServiceTestCase {
    
    private AuthenticationToken admin;
    private ServiceSessionRemote serviceSession;
    
    private static final String[] INFO_ARGS = { "info" }; 
    
    protected AuthenticationToken getAdmin() throws ErrorAdminCommandException {
        if (admin == null) {
            ServiceInfoCommand cmd = new ServiceInfoCommand(); // any command extending BaseServiceCommand
            cmd.execute(INFO_ARGS); // execute logs in also
            admin = cmd.getAdmin();
        }
        return admin;
    }
    
    protected ServiceSessionRemote getServiceSession() {
        if (serviceSession == null) {
            serviceSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ServiceSessionRemote.class);
        }
        return serviceSession;
    }
}

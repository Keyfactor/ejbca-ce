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
 
package se.anatom.ejbca.admin;

import java.rmi.RemoteException;

import javax.ejb.CreateException;
import javax.naming.Context;
import javax.naming.NamingException;

import org.apache.log4j.PropertyConfigurator;

import se.anatom.ejbca.upgrade.IUpgradeSessionRemote;
import se.anatom.ejbca.upgrade.IUpgradeSessionHome;

/**
 * Implements call to the upgrade function
 *
 * @version $Id: Upgrade.java,v 1.4 2004-04-16 08:17:25 anatom Exp $
 */
public class Upgrade extends BaseCommand {

    /**
     * 
     */
    public Upgrade() {
        super();
    }
    
    public boolean upgrade() {
     debug(">upgrade");
     String database = System.getProperty("ejbcaDB");
     debug("ejbcaDB="+database);
     String datasource = System.getProperty("ejbcaDS");
     debug("ejbcaDS="+datasource);
     
     // Check prerequisited
     if (!appServerRunning()) {
        error("The application server must be running.");
        return false;
     }
     try {
        IUpgradeSessionRemote upgradesession = getUpgradeSessionRemote();
        String[] args = new String[2];
        args[0] = database;
        args[1] = datasource;
        upgradesession.upgrade(administrator, args);
     } catch (Exception e) {
     	error("Can't upgrade: ", e);
     }
     debug("<upgrade");
     return false;
    }

    protected IUpgradeSessionRemote getUpgradeSessionRemote() throws NamingException, CreateException, RemoteException {
        Context ctx = getInitialContext();
        IUpgradeSessionHome home = (IUpgradeSessionHome) javax.rmi.PortableRemoteObject.narrow(ctx.lookup("UpgradeSession"), IUpgradeSessionHome.class );            
        IUpgradeSessionRemote upgradesession = home.create();          
        return upgradesession;
     }
    
    /**
     * main RA
     *
     * @param args command line arguments
     */
    public static void main(String[] args) {
        PropertyConfigurator.configure("log4j.properties");

        Upgrade upgrade = new Upgrade();
        try {
            boolean ret = upgrade.upgrade();
            if (!ret) {
                upgrade.error("Upgrade not performed.");
            } else {
             upgrade.info("Upgrade completed.");   
            }
        } catch (Exception e) {
            //System.out.println(e.getMessage());
            upgrade.error("Error doing upgrade: ", e);
            System.exit(-1);
        }
    }

}

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
 * @version $Id: Upgrade.java,v 1.2 2004-04-15 13:45:01 anatom Exp $
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
        upgradesession.upgrade(administrator);
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

package se.anatom.ejbca.admin;

import org.apache.log4j.PropertyConfigurator;


/**
 * Implements call to the upgrade function
 *
 * @version $Id: Upgrade.java,v 1.1 2004-04-10 17:12:48 anatom Exp $
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
     error("ejbcaDB="+database);
     String datasource = System.getProperty("ejbcaDS");
     error("ejbcaDS="+datasource);
     
     // Check prerequisited
     if (!appServerRunning()) {
        error("The application server must be running.");
        return false;
     }
     debug("<upgrade");
     return false;
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

package se.anatom.ejbca.admin;

import org.apache.log4j.PropertyConfigurator;


/**
 * Implements the CA command line interface
 *
 * @version $Id: ca.java,v 1.32 2003-08-20 09:50:11 anatom Exp $
 */
public class ca {
    /**
     * Main
     *
     * @param args command line arguments
     */
    public static void main(String[] args) {
        PropertyConfigurator.configure("log4j.properties");

        try {
            IAdminCommand cmd = CaAdminCommandFactory.getCommand(args);

            if (cmd != null) {
                cmd.execute();
            } else {
                System.out.println(
                    "Usage: CA info | makeroot | getrootcert | makereq | recrep | processreq | init | createcrl | getcrl | rolloverroot | rolloversub | listexpired | exportprofiles | importprofiles");
            }
        } catch (Exception e) {
            System.out.println(e.getMessage());

            //e.printStackTrace();
        }
    }
}


//ca

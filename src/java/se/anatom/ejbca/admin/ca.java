package se.anatom.ejbca.admin;

import org.apache.log4j.PropertyConfigurator;


/**
 * Implements the CA command line interface
 *
 * @version $Id: ca.java,v 1.30 2003-06-26 11:43:22 anatom Exp $
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
                    "Usage: CA info | makeroot | getrootcert | makereq | recrep | processreq | init | createcrl | getcrl | rolloverroot | rolloversub | listexpired");
            }
        } catch (Exception e) {
            System.out.println(e.getMessage());

            //e.printStackTrace();
        }
    }
}


//ca

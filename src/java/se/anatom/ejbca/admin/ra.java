package se.anatom.ejbca.admin;

import org.apache.log4j.PropertyConfigurator;


/**
 * Implements the RA command line interface
 *
 * @version $Id: ra.java,v 1.25 2004-04-10 17:12:26 anatom Exp $
 */
public class ra extends BaseCommand {
    /**
     * main RA
     *
     * @param args command line arguments
     */
    public static void main(String[] args) {
        PropertyConfigurator.configure("log4j.properties");

        try {
            IAdminCommand cmd = RaAdminCommandFactory.getCommand(args);

            if (cmd != null) {
                cmd.execute();
            } else {
                System.out.println(
                    "Usage: RA adduser | deluser | setpwd | setclearpwd | setuserstatus | finduser | listnewusers | listusers | revokeuser | keyrecover | keyrecovernewest");
            }
        } catch (Exception e) {
            System.out.println(e.getMessage());
            //e.printStackTrace();
            System.exit(-1);
        }
    }
}

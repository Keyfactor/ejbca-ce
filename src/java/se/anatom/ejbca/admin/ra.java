package se.anatom.ejbca.admin;

import org.apache.log4j.PropertyConfigurator;

public class ra {

    public static void main(String [] args){
        PropertyConfigurator.configure("log4j.properties");
        try {
            IAdminCommand cmd = RaAdminCommandFactory.getCommand(args);
            if (cmd != null) {
                cmd.execute();
            } else {
            System.out.println("Usage: RA adduser | deluser | setpwd | setclearpwd | setuserstatus | finduser | listnewusers | listusers | revokeuser | keyrecover | keyrecovernewest");
            }
        } catch (Exception e) {
            System.out.println(e.getMessage());
            //e.printStackTrace();
        }
    }

}

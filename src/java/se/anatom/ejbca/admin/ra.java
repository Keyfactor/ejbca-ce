package se.anatom.ejbca.admin;

import java.io.*;

public class ra {

    public static void main(String [] args){
        org.apache.log4j.PropertyConfigurator.configure("log4j.properties");
        try {
            IAdminCommand cmd = RaAdminCommandFactory.getCommand(args);
            if (cmd != null) {
                cmd.execute();
            } else {
            System.out.println("Usage: RA adduser | deluser | setpwd | setclearpwd | setuserstatus | finduser | listnewusers | listusers | revokeuser");
            }
        } catch (Exception e) {
            System.out.println(e.getMessage());
            //e.printStackTrace();
        }
    }

}

package se.anatom.ejbca.admin;

import java.io.*;

public class ca {

    public static void main(String [] args){
        org.apache.log4j.PropertyConfigurator.configure("log4j.properties");
        try {
            IAdminCommand cmd = CaAdminCommandFactory.getCommand(args);
            if (cmd != null) {
                cmd.execute();
            } else {
                System.out.println("Usage: CA info | makeroot | getrootcert | makereq | recrep | processreq | init | createcrl | getcrl | rolloverroot | rolloversub | listexpired");
            }
        } catch (Exception e) {
            System.out.println(e.getMessage());
            //e.printStackTrace();
        }
    }


} //ca

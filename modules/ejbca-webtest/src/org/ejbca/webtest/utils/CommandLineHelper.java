package org.ejbca.webtest.utils;

public class CommandLineHelper {


    /**
     * Run the designated command line method.
     *
     * @param cmd command to run.
     * @return isSuccessful
     */
    public Boolean runCommand(String cmd) {
        Boolean isSuccessful = false;

        try {
            Runtime rt = Runtime.getRuntime();
            Process pr = rt.exec(cmd);
            isSuccessful = true;
            return isSuccessful;
        } catch (Exception e) {
            e.printStackTrace();
            return isSuccessful;
        }

    }


}

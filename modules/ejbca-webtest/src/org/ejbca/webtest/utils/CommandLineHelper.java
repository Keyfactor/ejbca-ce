package org.ejbca.webtest.utils;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.concurrent.Executors;
import java.util.function.Consumer;

public class CommandLineHelper {


    /**
     * Run the designated command line method.
     *
     * @param cmd command to run.
     * @return isSuccessful
     */
    public Boolean runCommand(String cmd) {
        Boolean isSuccessful = false;
        String whichOS = System.getProperty("os.name");
        Boolean isWindows = true;


        if (!whichOS.toLowerCase().startsWith("windows")) {
            isWindows = false;
        }

        Process process = null;
        try {
            if (isWindows) {
                process = Runtime.getRuntime()
                        .exec("cmd.exe " + cmd);

            } else {
                process = Runtime.getRuntime()
                        .exec(cmd);
            }

            StreamGobbler streamGobbler =
                    new StreamGobbler(process.getInputStream(), System.out::println);
            Executors.newSingleThreadExecutor().submit(streamGobbler);
            int exitCode = process.waitFor();
            System.out.println("Exit Code:  " + exitCode);
            assert exitCode == 0;
            isSuccessful = true;
        } catch (Exception e) {
            e.printStackTrace();
        }

        return isSuccessful;
    }

    private static class StreamGobbler implements Runnable {
        private InputStream inputStream;
        private Consumer<String> consumer;

        public StreamGobbler(InputStream inputStream, Consumer<String> consumer) {
            this.inputStream = inputStream;
            this.consumer = consumer;
        }

        @Override
        public void run() {
            new BufferedReader(new InputStreamReader(inputStream)).lines()
                    .forEach(consumer);
        }
    }

}

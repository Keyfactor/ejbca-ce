package org.ejbca.webtest.utils;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Comparator;

import org.apache.log4j.Logger;

public class RemoveDir {

    private static final Logger log = Logger.getLogger(RemoveDir.class);

    private Path path;

    public RemoveDir(String sPath) {
        this.path = Paths.get(sPath);
    }

    /**
     * Remove list of files in directory and the directory itself.
     * Logs an info message, but does not throw exception, if the directory does not exist.
     */
    public void deleteDirectoryStream() {
        try {
            Files.walk(path)
                    .sorted(Comparator.reverseOrder())
                    .map(Path::toFile)
                    .forEach(File::delete);
        } catch (IOException e) {
            log.info("Failed to remove directory " + path);
        }
    }
}

package org.ejbca.webtest.utils;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Comparator;

public class RemoveDir {
    Path path;

    public RemoveDir(String sPath) {
        this.path = Paths.get(sPath);
    }

    /**
     * Remove list of files in directory and the directory itself.
     *
     * @throws IOException
     */
    public void deleteDirectoryStream() throws IOException {
        Files.walk(this.path)
                .sorted(Comparator.reverseOrder())
                .map(Path::toFile)
                .forEach(File::delete);
    }
}

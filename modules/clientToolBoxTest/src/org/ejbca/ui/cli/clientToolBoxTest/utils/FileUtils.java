package org.ejbca.ui.cli.clientToolBoxTest.utils;

import java.io.File;
import java.net.URISyntaxException;

/**
 * Miscellaneous file related utilities.
 * @author lars
 *
 */
public class FileUtils {

	/**
	 * The directory of the jar file of the current source.
	 */
	final public static File jarDir;
	static {
		try {
			jarDir = new File(FileUtils.class.getProtectionDomain().getCodeSource().getLocation().toURI().getPath()).getParentFile();
		} catch (URISyntaxException e) {
			e.printStackTrace();
			throw new Error(e);
		}
	}
}

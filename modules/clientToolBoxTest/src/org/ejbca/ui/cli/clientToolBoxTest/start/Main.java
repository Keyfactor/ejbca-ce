/**
 * 
 */
package org.ejbca.ui.cli.clientToolBoxTest.start;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.Constructor;
import java.security.Permission;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

import org.ejbca.ui.cli.clientToolBoxTest.tests.CommandLine;
import org.ejbca.ui.cli.clientToolBoxTest.utils.ExitException;
import org.ejbca.ui.cli.clientToolBoxTest.utils.FileUtils;
import org.ejbca.ui.cli.clientToolBoxTest.utils.SystemInRedirect;
import org.ejbca.ui.cli.clientToolBoxTest.utils.SystemOutStorage;
import org.testng.TestNG;
import org.testng.reporters.XMLReporter;
import org.testng.xml.XmlClass;
import org.testng.xml.XmlSuite;
import org.testng.xml.XmlTest;

import se.primeKey.pkcs11.SystemInit;

/**
 * Class with the {@link #main(String[])} method of the test application.
 * @author lars
 *
 */
public class Main {


	private static void printHelp(final File jarDir) throws IOException {
		final StringWriter sw = new StringWriter();
		final PrintWriter pw = new PrintWriter(sw);
		pw.println("In the distribution you may choose between any of these predefined test suites:");
		for ( final File f : jarDir.listFiles() ) {
			pw.print("    ");
			final String name = f.getName();
			if ( !name.endsWith(".xml") ) {
				continue;
			}
			pw.println(name.substring(0, name.length()-4));
		}
		pw.println("Give all suites that you want tested as an argument to the command.");
		pw.println("Or you may also specify path names for valid xml files in the file system.");
		pw.println("The directory '"+jarDir.getCanonicalPath()+"' contains files defining the suites.");
		System.err.println(sw.toString());
	}
	private static void loadNeededProviders() {
		final Provider p;
		try {
			// use reflection because the provider is not in java7 (ec is part of other providers.)
			// this is not needed on debian since the provider is already installed.
			final Class<?> cl = Class.forName("sun.security.ec.SunEC");
			final Constructor<?> constructor = cl.getConstructor(new Class[]{});
			p = (Provider)constructor.newInstance();
		} catch (Exception e) {
			return;
		}
		Security.addProvider(p);
	}
	private static class NoExitSecurityManager extends SecurityManager {
		private boolean isEnabled;
		NoExitSecurityManager() {
			super();
			this.isEnabled = true;
		}

		void disable() {
			this.isEnabled = false;
		}

		@Override
		public void checkExit( int status ) {
			if ( this.isEnabled ) {
				throw new ExitException(status);
			}
		}

		@Override
		public void checkPermission(Permission perm) {
			// allow
		}

		@Override
		public void checkPermission(Permission perm, Object context) {
			// allow
		}
	}
	private static class MyTestNG extends TestNG {
		@Override
		public void run() {
			initializeSuitesAndJarFile();
			for ( final XmlSuite s : this.m_suites ) {
				final Class<? extends Object> defaultClass;
				try {
					final String sDefaultClass = s.getParameter("defaultClass");
					defaultClass = sDefaultClass!=null && sDefaultClass.length()>0 ? Class.forName(sDefaultClass) : CommandLine.class;
				} catch (ClassNotFoundException e) {
					throw new Error(e);
				}
				for (final XmlTest t : s.getTests() ) {
					final List<XmlClass> oldList = t.getClasses();
					if ( oldList!=null && oldList.size()>0 ) {
						continue;
					}
					final List<XmlClass> newList = new LinkedList<>();
					newList.add(new XmlClass(defaultClass, true));
					t.setClasses(newList);
				}
			}
			super.run();
		}
	}
	private static void start(String[] args, final SecurityManager nesm ) throws Exception {
		SystemOutStorage.initiate();
		SystemInRedirect.initiate();
		SystemInit.doIt();
		final List<String> suites = new LinkedList<>();
		final File jarDir = new File(FileUtils.jarDir, "resources/suites");
		for ( final String name : args) {
			if ( name==null ) {
				printHelp(jarDir);
				System.exit(-1);
			}
			final File absoluteFile = new File(name);
			if ( absoluteFile.canRead() ) {
				suites.add(absoluteFile.getCanonicalPath());
				continue;
			}
			final File suiteFile = new File(jarDir, name+".xml");
			if ( !suiteFile.canRead() ) {
				System.err.println('\''+name+"' is neither a valid suite nor a readable file.");
				System.exit(-1);
			}
			suites.add(suiteFile.getCanonicalPath());
		}
		if ( suites.isEmpty() ) {
			printHelp(jarDir);
			System.exit(-1);
		}
		@SuppressWarnings("synthetic-access")
		final Main.MyTestNG testng = new Main.MyTestNG();
		testng.setUseDefaultListeners(false);
		testng.setTestSuites(suites);
//		testng.setSuiteThreadPoolSize(Integer.valueOf(suites.size()));
		testng.setListenerClasses(Arrays.asList(new Class[] {
				LoggerListener.class,
//				VerboseReporter.class,
				Class.forName("org.uncommons.reportng.HTMLReporter"),
				XMLReporter.class
		}));
		loadNeededProviders();
		System.setSecurityManager(nesm);
		testng.run();
	}
	/**
	 * Start of TestNG
	 * @param args Each element is the name of a predefined suite or a file that defines a suite.
	 */
	public static void main(String[] args) {
		final NoExitSecurityManager nesm = new NoExitSecurityManager();
		try {
			start(args, nesm);
		} catch (Throwable e) {
			nesm.disable();
			e.printStackTrace(System.err);
			System.exit(-1);
		}
	}
}

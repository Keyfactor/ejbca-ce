/**
 * 
 */
package org.ejbca.ui.cli.clientToolBoxTest.tests;

import static org.testng.Assert.assertEquals;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.ejbca.ui.cli.clientToolBoxTest.utils.ExitException;
import org.ejbca.ui.cli.clientToolBoxTest.utils.SystemInRedirect;
import org.ejbca.ui.cli.clientToolBoxTest.utils.SystemOutStorage;
import org.testng.annotations.Optional;
import org.testng.annotations.Parameters;
import org.testng.annotations.Test;

/**
 * <h1>
 * Test of a command.
 * </h1>
 * <p>
 * Contains the test method {@link #commandExecution(String, String, String)} that is used
 * to execute a clientToolBox command line.
 * </p>
 * @author lars
 *
 */
public class CommandLine {

	private final static Logger logger = Logger.getLogger( CommandLine.class.getCanonicalName());

	private static String[] getArguments( final String s ) {
		final List<String> list = new ArrayList<>();
		/*
		[^"]	- token starting with something else than "
		\S*		- followed by zero or more non-space characters
		...or...
		".+?"	- a "-symbol followed by whatever, until another ".
		 */
		final Matcher m = Pattern.compile("([^\"]\\S*|\".+?\")\\s*").matcher(s);
		while (m.find()) {
			list.add(m.group(1).replace("\"", ""));
		}
		return list.toArray(new String[0]);
	}

	final private static boolean hasStdError( final String s ) {
		if ( s.length()==0 ) {// nothing is good
			return false;
		}
		if ( s.indexOf('\n')>0 ) {// no newline (only one ask for password line)
			return true;
		}
		final String sPass = "Password: ";// password prompt must be last if valid ask for password
		if ( s.indexOf(sPass)+sPass.length()!=s.length() ) {
			return true;
		}
		return false;// must be an ask for password
	}

	protected static final Method getClientToolBoxMainMethod() throws Exception {
		final Class<?> cls = Class.forName("org.ejbca.ui.cli.ClientToolBox");
		return cls.getMethod("main", String[].class);
	}

	@SuppressWarnings("static-method")
	protected String formatCommandLine(final String line) {
		return line;
	}

	/**
	 * <h5>
	 * Command line execution.
	 * </h5><p>
	 * Executes a clientToolBox command line. Checks the return code and if
	 * something is sent to standard error.
	 * </p><p>
	 * Each argument is defined with a TestNG parameter that has the same name.
	 * </p>
	 * @param commandLine the line.
	 * @param statusCode the expected status code. Defaults to '0' if the TestNG parameter is not existing.
	 * @param hasStdError true if stderr output is expected. Defaults to 'false' if the TestNG parameter is not existing.
	 * @throws Exception
	 */
	@Parameters({ "commandLine", "statusCode", "hasStdError" })
	@Test(groups = { "cli" })
	public void commandExecution(
			final String commandLine,
			@Optional("0") final String statusCode,
			@Optional("false") final String hasStdError) throws Exception{
		final SystemOutStorage.StdStrings result;
		try {
			SystemOutStorage.start();
			SystemInRedirect.setInput("x");
			getClientToolBoxMainMethod().invoke(null, (Object)getArguments(formatCommandLine(commandLine))); // static method doesn't have an instance
		} catch( InvocationTargetException e ) {
			final Throwable t = e.getCause();
			if ( t!=null && t instanceof ExitException && statusCode.toLowerCase().indexOf("nostatuscheck")<0 ) {
				final ExitException ee = (ExitException)t;
				assertEquals(ee.status, Integer.parseInt(statusCode), "Command with non expected status code");
			}
		} finally {
			result = SystemOutStorage.getOutput();
		}
		final StringWriter sw = new StringWriter();
		final PrintWriter pw = new PrintWriter(sw);
		pw.print("Output from \"");
		pw.print(commandLine);
		pw.println("\":");
		pw.println("<<<<<<<<<<<<<<<<<<< Error Start");
		pw.println("\""+result.err+"\"");
		pw.println(">>>>>>>>>>>>>>>>>>> Error End");
		pw.println("<<<<<<<<<<<<<<<<<<< Stdout Start");
		pw.println(result.out);
		pw.println(">>>>>>>>>>>>>>>>>>> Stdout End");
		pw.flush();
		logger.info(sw.toString());
		assertEquals(hasStdError(result.err), hasStdError.toLowerCase().indexOf("true")>-1, "Not expected stderror. See log.");
	}
}

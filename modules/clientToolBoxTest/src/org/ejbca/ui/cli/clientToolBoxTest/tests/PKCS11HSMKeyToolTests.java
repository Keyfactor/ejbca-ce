/**
 * 
 */
package org.ejbca.ui.cli.clientToolBoxTest.tests;

import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;

import org.ejbca.ui.cli.clientToolBoxTest.utils.FileUtils;
import org.testng.annotations.BeforeSuite;
import org.testng.annotations.Optional;
import org.testng.annotations.Parameters;

import se.primeKey.pkcs11.P11Module;
import se.primeKey.x509.StreamUtils;

/**
 * <h1>
 * Test of a PKCS#11 command.
 * </h1>
 * <p>
 * This class makes sure that 2 test tokens are created
 * ({@link #prepareToken(String)}) before any
 * {@link #commandExecution(String, String, String)} call is made on any
 * instance belonging to this class.
 * </p><p>
 * Later when a {@link #commandExecution(String, String, String)} is called
 * placeholders in the command line are replaced by information about the
 * tokens.
 * </p><p>
 * Configuration files are also created by replacing placeholders in template
 * files located in $TEST_HOME/resources/p11conf and then storing them in the
 * current directory ({@link #createP11configFiles()}).
 * </p><p>
 * These are the placeholders and a definition of what is replaced:
 * <ul>
 * <li>${ix_n} the position of token 'n' in the slot list.</li>
 * <li>${id_n} the id (integer) of token 'n'.</li>
 * <li>${label_n} the name of the label for token 'n'.</li>
 * <li>${userPass_n} the user password for token 'n'.</li>
 * <li>${p11m} path to the p11 shared library.</li>
 * <li>${batchGenerateFile} path to a file with keys to be batch generated on a token.</li>
 * </ul>
 * 'n' is the number of the token (1 or 2).
 * </p>
 * @author lars
 *
 */
public class PKCS11HSMKeyToolTests extends CommandLine {

	protected static class TokenInfo {
		final String label;
		private final long id;
		private final int ix;
		private final String suffix;
		final String userPass;
		private TokenInfo(
				final String _label,
				final long _id,
				final int _ix,
				final String _suffix,
				final String _userPass) {
			this.label = _label;
			this.id = _id;
			this.ix = _ix;
			this.suffix = _suffix;
			this.userPass = _userPass;
		}
		public String replacePlaceHolders(final StringBuilder builder) {
			formatWithSuffix(builder, "ix", Integer.toString(this.ix));
			formatWithSuffix(builder, "id", Long.toString(this.id));
			formatWithSuffix(builder, "label", this.label);
			formatWithSuffix(builder, "userPass", this.userPass);
			return builder.toString();
		}
		public static void format(final StringBuilder builder, final String key, final String value) {
			final String pattern = "${" + key + "}";

			// Replace every occurrence of ${key} with value
			while ( true ) {
				final int start = builder.indexOf(pattern);
				if ( start<0 ) {
					break;
				}
				builder.replace(start, start + pattern.length(), value);
			}
		}
		private void formatWithSuffix(final StringBuilder builder, final String key, final String value) {
			format(builder, key+this.suffix, value);
		}
		static TokenInfo getInstance(
				final P11Module p11m, final String label,
				final String soPass, final String userPass, final String suffix) throws Exception {
			final long id = p11m.initializeToken(label, soPass, userPass);
			final int ix = p11m.getSlotListIx(id);
			return new TokenInfo(label, id, ix, suffix, userPass);
		}
	}

	protected static class TestTokens {
		final TokenInfo tokenInfo1;
		final TokenInfo tokenInfo2;
		final private String canonicalP11m;
		final public P11Module p11m;
		final private String batchGenerateFile;
		TestTokens(final String sP11m, final String userPass1, final String userPass2) throws Exception {
			this.canonicalP11m = new File(sP11m).getCanonicalFile().getCanonicalPath();
			this.p11m = P11Module.getInstance(sP11m);
			this.tokenInfo1 = TokenInfo.getInstance(this.p11m, "receiver", "officerPass", userPass1, "_1");
			this.tokenInfo2 = TokenInfo.getInstance(this.p11m, "sender", "officerPass", userPass2, "_2");
			assertNotNull(this.tokenInfo1);
			assertNotNull(this.tokenInfo2);
			final File fBatchG = new File(FileUtils.jarDir, "resources/batchGenerate.txt");
			assertTrue( fBatchG.canRead() );
			this.batchGenerateFile = fBatchG.getCanonicalPath();
		}
		public String format(final String s) {
			final StringBuilder builder = new StringBuilder(s);
			this.tokenInfo1.replacePlaceHolders(builder);
			this.tokenInfo2.replacePlaceHolders(builder);
			TokenInfo.format(builder, "p11m", this.canonicalP11m);
			TokenInfo.format(builder, "batchGenerateFile", this.batchGenerateFile);
			return builder.toString();
		}
	}

	protected static TestTokens tokenObject;

	/**
	 * <h5>
	 * Creates test tokens before any tests in the suite are started.
	 * </h5><p>
	 * The argument is defined with a TestNG parameter that has the same name.
	 * </p>
	 * @param p11module The path to the p11 module shared library. Specified in the TestNG xml as 'p11module'.
	 * @throws Exception
	 */
	@BeforeSuite
	@Parameters({"p11module"})
	public static void prepareToken(@Optional("") final String p11module) throws Exception {
		if ( tokenObject!=null || p11module==null || p11module.length()<1 ) {
			return;
		}
		tokenObject = new TestTokens(p11module, "userPass1", "userPass2");
	}

	private static void createP11configFile(final File file) throws Exception {
		final ByteArrayOutputStream baos = new ByteArrayOutputStream();
		try ( final InputStream is = new FileInputStream(file) ) {
			StreamUtils.toOutputStream(is, baos);
		}
		final String sFile = baos.toString();
		final String sFormatedFile = tokenObject.format(sFile);
		try ( final OutputStream os = new FileOutputStream(file.getName()) ) {
			os.write(sFormatedFile.getBytes());
		}
	}

	/**
	 * <h5>
	 * Creates p11 configuration files.
	 * </h5><p>
	 * See {@link PKCS11HSMKeyToolTests}.
	 * Executed after {@link #prepareToken(String)}.
	 * </p>
	 * @throws Exception
	 */
	@BeforeSuite(dependsOnMethods="prepareToken")
	public static void createP11configFiles() throws Exception {
		if ( tokenObject==null ) {
			return;
		}
		final File dir = new File(FileUtils.jarDir, "resources/p11conf");
		final File files[] = dir.listFiles();
		for ( final File file : files ) {
			createP11configFile(file);
		}
	}

	@Override
	protected String formatCommandLine(final String line) {
		return tokenObject!=null ? tokenObject.format(line) : line;
	}
}

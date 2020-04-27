/**
 * 
 */
package org.ejbca.ui.cli.clientToolBoxTest.utils;

/**
 * Exception that is thrown by a custom {@link SecurityManager} not allowing
 * {@link System#exit(int)}.
 * @author lars
 *
 */
public class ExitException extends SecurityException {

	/**
	 * version
	 */
	private static final long serialVersionUID = 1L;

	/**
	 * The status of the {@link System#exit(int)} call.
	 */
	public final int status;
	/**
	 * @param s the status.
	 */
	public ExitException( final int s ) {
		super("System.exit(n) called. n="+s);
		this.status = s;
	}
}

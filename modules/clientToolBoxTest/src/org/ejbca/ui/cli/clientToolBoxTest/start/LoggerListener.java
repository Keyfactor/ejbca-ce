package org.ejbca.ui.cli.clientToolBoxTest.start;

import java.util.logging.Level;
import java.util.logging.Logger;

import org.testng.ITestContext;
import org.testng.ITestNGListener;
import org.testng.ITestResult;
import org.testng.TestListenerAdapter;
import org.testng.TestNG;

/**
 * <h1>
 * Java logging listener.
 * </h1><p>
 * This is a {@link ITestNGListener} that writes {@link TestNG} logging to
 * {@link Logger}.
 * It is added by a {@link TestNG#setListenerClasses(java.util.List)} before the
 * the test is started.
 * </p>
 * @author lars
 *
 */
public class LoggerListener extends TestListenerAdapter {
	private final static Logger logger = Logger.getLogger( LoggerListener.class.getCanonicalName());

	private static void getMessage(
			final ITestResult result,
			final String message,
			final boolean isDone) {
		final StringBuffer sb = new StringBuffer();
		sb.append(result.getTestContext().getName());
		sb.append("::");
		sb.append(result.getName());
		sb.append('\t');
		sb.append(message);
		if ( !isDone || result.isSuccess() ) {
			logger.fine(sb.toString());
			return;
		}
		if ( result.getThrowable()==null ) {
			logger.severe(sb.toString());
			return;
		}
		logger.log(Level.SEVERE, sb.toString(), result.getThrowable());
	}

	/**
	 * Called by TestNG when the test is starting.
	 */
	public LoggerListener(){
		super();
	}

	@Override
	public void onConfigurationFailure(ITestResult itr) {
		super.onConfigurationFailure(itr);
		getMessage(itr, "Configuration failed", true);
	}

	@Override
	public void onConfigurationSkip(ITestResult itr) {
		super.onConfigurationSkip(itr);
		getMessage(itr, "Configuration skipped", false);
	}

	@Override
	public void onConfigurationSuccess(ITestResult itr) {
		super.onConfigurationSuccess(itr);
		getMessage(itr, "Configuration succeeded.", true);
	}

	@Override
	public void onFinish(ITestContext context) {
		super.onFinish(context);
		final StringBuilder stringBuilder = new StringBuilder();
		stringBuilder.append(context.getName());
		stringBuilder.append(" finished.");
		logger.fine(stringBuilder.toString());
	}

	@Override
	public void onStart(ITestContext context) {
		super.onStart(context);
		logger.fine(context.getName()+" started.");
	}

	@Override
	public void onTestFailedButWithinSuccessPercentage(ITestResult result) {
		super.onTestFailedButWithinSuccessPercentage(result);
		getMessage(result, "Test failure but within success percentage", true);
	}

	@Override
	public void onTestFailure(ITestResult result) {
		super.onTestFailure(result);
		getMessage(result, "Test failure", true);
	}

	@Override
	public void onTestSkipped(ITestResult result) {
		super.onTestSkipped(result);
		getMessage(result, "Test skipped", false);
	}

	@Override
	public void onTestStart(ITestResult result) {
		super.onTestStart(result);
		getMessage(result, "Test started", false);
	}

	@Override
	public void onTestSuccess(ITestResult result) {
		super.onTestSuccess(result);
		getMessage(result, "Test succeded", true);
	}
}
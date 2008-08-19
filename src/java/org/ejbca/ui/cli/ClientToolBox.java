/**
 * 
 */
package org.ejbca.ui.cli;

/**
 * @author lars
 *
 */
public abstract class ClientToolBox {

    abstract void execute(String[] args);
    abstract String getName();
    void executeIfSelected(String args[]) {
        if (args[0].equalsIgnoreCase(getName()))
            execute(args);
    }
    /**
     * @param args
     */
    public static void main(String[] args) {
        final ClientToolBox toolBox[] = { new HealthCheckTest() };
        if ( args.length<1 ) {
            System.err.println("You must specify which tool to use as first argument.");
            System.err.println("These tools are awailable:");
            for ( int i=0; i<toolBox.length; i++)
                System.err.println(" - "+toolBox[i].getName());
            return;
        }
        for ( int i=0; i<toolBox.length; i++)
            toolBox[i].executeIfSelected(args);
    }

}

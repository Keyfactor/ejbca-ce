package se.anatom.ejbca.apply;

import java.io.*;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
    /**
     * Prints debug info back to browser client
     **/
    public class ServletDebug {
        final private ByteArrayOutputStream buffer;
        final private PrintStream printer;
        final private HttpServletRequest request;
        final private HttpServletResponse response;
        ServletDebug(HttpServletRequest request, HttpServletResponse response){
            buffer=new ByteArrayOutputStream();
            printer=new PrintStream(buffer);
            this.request=request;
            this.response=response;
        }

        void printDebugInfo() throws IOException, ServletException {
            request.setAttribute("ErrorMessage",new String(buffer.toByteArray()));
            request.getRequestDispatcher("error.jsp").forward(request, response);
        }

        void print(Object o) {
            printer.println(o);
        }
        void printMessage(String msg) {
            print("<p>"+msg);
        }
        void printInsertLineBreaks( byte[] bA ) throws Exception {
            BufferedReader br=new BufferedReader(
                new InputStreamReader(new ByteArrayInputStream(bA)) );
            while ( true ){
                String line=br.readLine();
                if (line==null)
                    break;
                print(line.toString()+"<br>");
            }
        }
        void takeCareOfException(Throwable t ) {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            t.printStackTrace(new PrintStream(baos));
            print("<h4>Exception:</h4>");
            try {
                printInsertLineBreaks( baos.toByteArray() );
            } catch (Exception e) {
                e.printStackTrace(printer);
            }
            request.setAttribute("Exception", "true");
        }
        void ieCertFix(byte[] bA) throws Exception {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            PrintStream tmpPrinter=new PrintStream(baos);
            RequestHelper.ieCertFormat(bA, tmpPrinter);
            printInsertLineBreaks(baos.toByteArray());
        }
    } // Debug

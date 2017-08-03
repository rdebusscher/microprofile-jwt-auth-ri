package be.atbash.mp.jwt.jaspic.common;


import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import javax.servlet.annotation.WebListener;

import be.atbash.mp.jwt.jaspic.AtbashMPServerAuthModule;
/**
 * 
 *
 *
 */
@WebListener
public class SamAutoRegistrationListener implements ServletContextListener {

    @Override
    public void contextInitialized(ServletContextEvent sce) {
        JaspicUtils.registerSAM(sce.getServletContext(), new AtbashMPServerAuthModule());
    }

    @Override
    public void contextDestroyed(ServletContextEvent arg0) {
        // NOOP
    }
}
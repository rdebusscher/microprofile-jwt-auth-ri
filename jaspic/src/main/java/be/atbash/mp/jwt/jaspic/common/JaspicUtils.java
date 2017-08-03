package be.atbash.mp.jwt.jaspic.common;


import be.atbash.mp.jwt.util.Utils;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.message.AuthStatus;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.callback.CallerPrincipalCallback;
import javax.security.auth.message.callback.GroupPrincipalCallback;
import javax.security.auth.message.config.AuthConfigFactory;
import javax.security.auth.message.module.ServerAuthModule;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Principal;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static java.lang.Boolean.TRUE;

/**
 *
 *
 *
 */
public final class JaspicUtils {

    private static final String AUTH_PARAMS = "security.message.request.authParams";
    private static final String PROGRAMMATIC_AUTHENTICATION = "security.authentication";

    private static final String LOGGEDIN_USERNAME = "security.message.loggedin.username";
    private static final String LOGGEDIN_ROLES = "security.message.loggedin.roles";
    private static final String DID_AUTHENTICATION = "security.message.request.didAuthentication";


    private static final String IS_MANDATORY = "javax.security.auth.message.MessagePolicy.isMandatory";
    private static final String REGISTER_SESSION = "javax.servlet.http.registerSession";

    private JaspicUtils() {
    }

    /**
     * Registers the given SAM using the standard JASPIC {@link AuthConfigFactory} but using a small set of wrappers that just
     * pass the calls through to the SAM.
     *
     * @param serverAuthModule
     */
    public static void registerSAM(ServletContext context, ServerAuthModule serverAuthModule) {
        AuthConfigFactory.getFactory().registerConfigProvider(new TestAuthConfigProvider(serverAuthModule), "HttpServlet",
                getAppContextID(context), "JSR375 authentication config provider");
    }

    public static String getAppContextID(ServletContext context) {
        return context.getVirtualServerName() + " " + context.getContextPath();
    }


    public static boolean isProtectedResource(MessageInfo messageInfo) {
        return Boolean.valueOf((String) messageInfo.getMap().get(IS_MANDATORY));
    }

    public static boolean isProgrammaticAuthentication(HttpServletRequest request) {
        return TRUE.equals(request.getAttribute(PROGRAMMATIC_AUTHENTICATION));
    }

    public static boolean isRegisterSession(MessageInfo messageInfo) {
        return Boolean.valueOf((String) messageInfo.getMap().get(REGISTER_SESSION));
    }

    @SuppressWarnings("unchecked")
    public static void setRegisterSession(MessageInfo messageInfo, String username, Set<String> roles) {
        messageInfo.getMap().put("javax.servlet.http.registerSession", TRUE.toString());

        HttpServletRequest request = (HttpServletRequest) messageInfo.getRequestMessage();
        request.setAttribute(LOGGEDIN_USERNAME, username);

        Set<String> allRoles = (Set<String>) request.getAttribute(LOGGEDIN_ROLES);

        if (allRoles == null) {
            allRoles = new HashSet<>(roles);
            request.setAttribute(LOGGEDIN_ROLES, allRoles);
        } else {
            allRoles.addAll(roles);
        }
    }

    public static void notifyContainerAboutLogin(Subject clientSubject, CallbackHandler handler, Principal callerPrincipal, Set<String> roles) {
        try {
            if (Utils.isEmpty(roles)) {
                handler.handle(new Callback[] {
                        new CallerPrincipalCallback(clientSubject, callerPrincipal) });
            } else {
                handler.handle(new Callback[] {
                        new CallerPrincipalCallback(clientSubject, callerPrincipal),
                        new GroupPrincipalCallback(clientSubject, roles.toArray(new String[roles.size()])) });
            }
        } catch (IOException | UnsupportedCallbackException e) {
            // Should not happen
            throw new IllegalStateException(e);
        }
    }

    public static void notifyContainerAboutLogin(Subject clientSubject, CallbackHandler handler, String username, List<String> roles) {

        try {
            // 1. Create a handler (kind of directive) to add the caller principal (AKA user principal =basically user name, or user id) that
            // the authenticator provides.
            //
            // This will be the name of the principal returned by e.g. HttpServletRequest#getUserPrincipal
            //
            // 2 Execute the handler right away
            //
            // This will typically eventually (NOT right away) add the provided principal in an application server specific way to the JAAS
            // Subject.
            // (it could become entries in a hash table inside the subject, or individual principles, or nested group principles etc.)

            handler.handle(new Callback[] { new CallerPrincipalCallback(clientSubject, username) });

            if (!Utils.isEmpty(roles)) {
                // 1. Create a handler to add the groups (AKA roles) that the authenticator provides.
                //
                // This is what e.g. HttpServletRequest#isUserInRole and @RolesAllowed for
                //
                // 2. Execute the handler right away
                //
                // This will typically eventually (NOT right away) add the provided roles in an application server specific way to the JAAS
                // Subject.
                // (it could become entries in a hash table inside the subject, or individual principles, or nested group principles etc.)

                handler.handle(new Callback[] { new GroupPrincipalCallback(clientSubject, roles.toArray(new String[roles.size()])) });
            }

        } catch (IOException | UnsupportedCallbackException e) {
            // Should not happen
            throw new IllegalStateException(e);
        }
    }

    /**
     * Should be called when the callback handler is used with the intention that an actual
     * user is going to be authenticated (as opposed to using the handler for the "do nothing" protocol
     * which uses the unauthenticated identity).
     *
     * @param request The involved HTTP servlet request.
     *
     */
    public static void setDidAuthentication(HttpServletRequest request) {
        request.setAttribute(DID_AUTHENTICATION, TRUE);
    }

}

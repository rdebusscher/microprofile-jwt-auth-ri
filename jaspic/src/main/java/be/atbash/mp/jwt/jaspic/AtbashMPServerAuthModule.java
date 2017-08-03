package be.atbash.mp.jwt.jaspic;


import be.atbash.mp.jwt.jaspic.common.JaspicUtils;
import org.eclipse.microprofile.jwt.JWTPrincipal;
import org.eclipse.microprofile.jwt.principal.JWTAuthContextInfo;
import org.eclipse.microprofile.jwt.principal.JWTCallerPrincipal;
import org.eclipse.microprofile.jwt.principal.JWTCallerPrincipalFactory;
import org.eclipse.microprofile.jwt.principal.ParseException;

import javax.enterprise.inject.spi.CDI;
import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.AuthStatus;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.MessagePolicy;
import javax.security.auth.message.config.ServerAuthContext;
import javax.security.auth.message.module.ServerAuthModule;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Map;
import java.util.Set;


/**
 *
 */
public class AtbashMPServerAuthModule implements ServerAuthModule {

    private CallbackHandler handler;
    private final Class<?>[] supportedMessageTypes = new Class[]{HttpServletRequest.class, HttpServletResponse.class};

    @Override
    public void initialize(MessagePolicy requestPolicy, MessagePolicy responsePolicy, CallbackHandler handler, Map options) throws AuthException {
        this.handler = handler;
    }

    /**
     * A Servlet Container Profile compliant implementation should return HttpServletRequest and HttpServletResponse, so
     * the delegation class {@link ServerAuthContext} can choose the right SAM to delegate to.
     */
    @Override
    public Class<?>[] getSupportedMessageTypes() {
        return supportedMessageTypes;
    }

    @Override
    public AuthStatus validateRequest(MessageInfo messageInfo, Subject clientSubject, Subject serviceSubject) throws AuthException {

        HttpServletRequest request = (HttpServletRequest) messageInfo.getRequestMessage();
        String authorizationHeader = request.getHeader("Authorization");
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer")) {

            try {
                String bearerToken = authorizationHeader.substring(7);
                JWTPrincipal jwtPrincipal = validate(bearerToken);

                Set<String> groups = jwtPrincipal.getGroups();

                if (groups.isEmpty()) {
                    groups = jwtPrincipal.getRoles();
                }

                // Install the JWT principal as the caller
                JaspicUtils.notifyContainerAboutLogin(clientSubject, handler, jwtPrincipal, groups);
            } catch (ParseException e) {
                throw new AuthException(e.getMessage());
            }


        }
        return AuthStatus.SUCCESS;
    }

    @Override
    public AuthStatus secureResponse(MessageInfo messageInfo, Subject serviceSubject) throws AuthException {
        return AuthStatus.SUCCESS;
    }

    /**
     * Called in response to a {@link HttpServletRequest#logout()} call.
     */
    @Override
    public void cleanSubject(MessageInfo messageInfo, Subject subject) throws AuthException {
        if (subject != null) {
            subject.getPrincipals().clear();
        }
    }

    protected JWTPrincipal validate(String bearerToken) throws ParseException {
        JWTAuthContextInfo authContextInfo = CDI.current().select(JWTAuthContextInfo.class).get();

        JWTCallerPrincipalFactory factory = JWTCallerPrincipalFactory.instance();
        JWTCallerPrincipal callerPrincipal = factory.parse(bearerToken, authContextInfo);
        return callerPrincipal;
    }
}
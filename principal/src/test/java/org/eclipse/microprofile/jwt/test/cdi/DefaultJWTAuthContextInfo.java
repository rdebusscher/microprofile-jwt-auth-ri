package org.eclipse.microprofile.jwt.test.cdi;

import org.eclipse.microprofile.jwt.principal.JWTAuthContextInfo;

import javax.enterprise.inject.Vetoed;
import java.security.interfaces.RSAPublicKey;

/**
 *
 */
@Vetoed
public class DefaultJWTAuthContextInfo implements JWTAuthContextInfo {

    private  RSAPublicKey signerKey;
    private String issuedBy;
    private int expGracePeriodSecs = 60;

    public DefaultJWTAuthContextInfo() {
    }

    public DefaultJWTAuthContextInfo(JWTAuthContextInfo authContextInfo) {
        this.signerKey = authContextInfo.getSignerKey();
        this.issuedBy = authContextInfo.getIssuedBy();
        this.expGracePeriodSecs = authContextInfo.getExpGracePeriodSecs();
    }

    @Override
    public RSAPublicKey getSignerKey() {
        return signerKey;
    }

    public void setSignerKey(RSAPublicKey signerKey) {
        this.signerKey = signerKey;
    }

    @Override
    public String getIssuedBy() {
        return issuedBy;
    }

    public void setIssuedBy(String issuedBy) {
        this.issuedBy = issuedBy;
    }

    @Override
    public int getExpGracePeriodSecs() {
        return expGracePeriodSecs;
    }

    public void setExpGracePeriodSecs(int expGracePeriodSecs) {
        this.expGracePeriodSecs = expGracePeriodSecs;
    }
}

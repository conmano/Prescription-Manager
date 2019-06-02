package edu.uw.medhas.mhealthsecurityframework.authentication;

import android.app.KeyguardManager;
import android.hardware.fingerprint.FingerprintManager;

/**
 * Created by medhas on 2/4/19.
 */

public class AuthenticationManagerFactory {
    private static AuthenticationManager sAuthenticationManagerInstance;

    public static void init(FingerprintManager fingerprintManager,
                            KeyguardManager keyguardManager) {
        if (fingerprintManager.isHardwareDetected()) {
            AuthenticationManagerFactory.sAuthenticationManagerInstance
                    = new FingerprintAuthenticationManager(fingerprintManager, keyguardManager);
        } else {
            AuthenticationManagerFactory.sAuthenticationManagerInstance
                    = new BasicAuthenticationManager();
        }
    }

    public static AuthenticationManager getAuthenticationManager() {
        return AuthenticationManagerFactory.sAuthenticationManagerInstance;
    }
}

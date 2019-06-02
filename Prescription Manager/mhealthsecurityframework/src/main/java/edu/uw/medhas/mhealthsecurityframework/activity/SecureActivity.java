package edu.uw.medhas.mhealthsecurityframework.activity;

import android.app.KeyguardManager;
import android.content.Intent;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.widget.Toast;

import edu.uw.medhas.mhealthsecurityframework.acl.service.AclServiceFactory;
import edu.uw.medhas.mhealthsecurityframework.authentication.AuthenticationManagerFactory;
import edu.uw.medhas.mhealthsecurityframework.storage.cache.SecureCacheHandler;
import edu.uw.medhas.mhealthsecurityframework.storage.exception.ReauthenticationException;
import edu.uw.medhas.mhealthsecurityframework.storage.external.SecureExternalFileHandler;
import edu.uw.medhas.mhealthsecurityframework.storage.internal.SecureInternalFileHandler;

/**
 * Created by medhasrivastava on 1/28/19.
 */

public class SecureActivity extends AppCompatActivity {
    private static final int REQUEST_CODE_CONFIRM_DEVICE_CREDENTIALS = 17;

    private SecureInternalFileHandler mSecureInternalFileHandler = null;
    private SecureExternalFileHandler mSecureExternalFileHandler = null;
    private SecureCacheHandler mSecureCacheHandler = null;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        mSecureInternalFileHandler = new SecureInternalFileHandler(getBaseContext());
        mSecureExternalFileHandler = new SecureExternalFileHandler(getBaseContext());
        mSecureCacheHandler = new SecureCacheHandler(getBaseContext());

        AuthenticationManagerFactory.init((FingerprintManager) getSystemService(FINGERPRINT_SERVICE),
                (KeyguardManager) getSystemService(KEYGUARD_SERVICE));
    }

    public AclServiceFactory getAclServiceFactory() {
        AclServiceFactory.init(getApplicationContext());
        return AclServiceFactory.getInstance();
    }

    public SecureInternalFileHandler getSecureInternalFileHandler() {
        return mSecureInternalFileHandler;
    }

    public SecureExternalFileHandler getSecureExternalFileHandler() {
        return mSecureExternalFileHandler;
    }

    public SecureCacheHandler getSecureCacheHandler() {
        return mSecureCacheHandler;
    }

    public void startAuthenticationProcess() {
        final KeyguardManager keyguardManager = (KeyguardManager) getSystemService(KEYGUARD_SERVICE);
        final Intent intent = keyguardManager.createConfirmDeviceCredentialIntent(null, null);
        if (intent != null) {
            startActivityForResult(intent, REQUEST_CODE_CONFIRM_DEVICE_CREDENTIALS);
        } else {
            Toast.makeText(getApplicationContext(),
                    "Error starting authentication process", Toast.LENGTH_LONG).show();
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (requestCode == REQUEST_CODE_CONFIRM_DEVICE_CREDENTIALS) {
            if (resultCode != RESULT_OK) {
                throw new ReauthenticationException();
            }
        } else {
            super.onActivityResult(requestCode, resultCode, data);
        }
    }
}

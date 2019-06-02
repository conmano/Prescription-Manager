package edu.uw.medhas.mhealthsecurityframework.authentication;

import android.app.KeyguardManager;
import android.hardware.fingerprint.FingerprintManager;
import android.os.CancellationSignal;

import java.util.Optional;

import edu.uw.medhas.mhealthsecurityframework.storage.encryption.EncryptionServiceCallback;
import edu.uw.medhas.mhealthsecurityframework.storage.result.StorageResultErrorType;

/**
 * Created by medhas on 2/4/19.
 */

public class FingerprintAuthenticationManager implements AuthenticationManager {
    private final FingerprintManager mFingerprintManager;
    private final KeyguardManager mKeyguardManager;

    private final CancellationSignal mSignal = new CancellationSignal();

    public FingerprintAuthenticationManager(FingerprintManager fingerprintManager,
                                            KeyguardManager keyguardManager) {
        mFingerprintManager = fingerprintManager;
        mKeyguardManager = keyguardManager;
    }

    @Override
    public Optional<Integer> getUserAuthenticationValidityDurationSeconds() {
        return Optional.empty();
    }

    @Override
    public void performAuthentication(FingerprintManager.CryptoObject cryptoObject,
                                      final EncryptionServiceCallback callback) {
        if (!mFingerprintManager.hasEnrolledFingerprints()) {
            callback.onFailure(StorageResultErrorType.NO_FINGERPRINT_AVAILABLE);
            return;
        } else if (!mKeyguardManager.isKeyguardSecure()) {
            callback.onFailure(StorageResultErrorType.KEUGUARD_UNSECURE);
            return;
        }

        mFingerprintManager.authenticate(cryptoObject,
                mSignal,
                0,
                new FingerprintManager.AuthenticationCallback() {
                    @Override
                    public void onAuthenticationError(int errorCode, CharSequence errString) {
                        callback.onFailure(StorageResultErrorType.AUTH_ERROR);
                    }

                    @Override
                    public void onAuthenticationHelp(int helpCode, CharSequence helpString) {
                        callback.onFailure(StorageResultErrorType.AUTH_HELP);
                    }

                    @Override
                    public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
                        callback.onSuccess(result.getCryptoObject().getCipher());
                    }

                    @Override
                    public void onAuthenticationFailed() {
                        callback.onFailure(StorageResultErrorType.FINGERPRINT_INVALID);
                    }
                }, null);

        callback.onWaitingForAuthentication();
    }
}

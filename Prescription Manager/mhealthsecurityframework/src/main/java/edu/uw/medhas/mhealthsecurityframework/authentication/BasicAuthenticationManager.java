package edu.uw.medhas.mhealthsecurityframework.authentication;

import android.hardware.fingerprint.FingerprintManager;

import java.util.Optional;

import edu.uw.medhas.mhealthsecurityframework.storage.encryption.EncryptionServiceCallback;

/**
 * Created by medhas on 2/4/19.
 */

public class BasicAuthenticationManager implements AuthenticationManager {
    @Override
    public Optional<Integer> getUserAuthenticationValidityDurationSeconds() {
        return Optional.of(60);
    }

    @Override
    public void performAuthentication(FingerprintManager.CryptoObject cryptoObject,
                                      EncryptionServiceCallback callback) {
        callback.onSuccess(cryptoObject.getCipher());
    }
}

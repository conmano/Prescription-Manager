package edu.uw.medhas.mhealthsecurityframework.authentication;

import android.hardware.fingerprint.FingerprintManager;

import java.util.Optional;

import edu.uw.medhas.mhealthsecurityframework.storage.encryption.EncryptionServiceCallback;

/**
 * Created by medhas on 2/4/19.
 */

public interface AuthenticationManager {
    Optional<Integer> getUserAuthenticationValidityDurationSeconds();

    void performAuthentication(FingerprintManager.CryptoObject cryptoObject,
                                 EncryptionServiceCallback callback);
}

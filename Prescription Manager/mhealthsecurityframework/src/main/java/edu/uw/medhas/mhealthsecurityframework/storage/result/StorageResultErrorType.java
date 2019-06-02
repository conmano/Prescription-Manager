package edu.uw.medhas.mhealthsecurityframework.storage.result;

/**
 * Created by medhas on 2/7/19.
 */

public enum StorageResultErrorType {
    SERIALIZATION_ERROR,
    DEFAULT_CONSTRUCTOR_ERROR,
    ENCRYPTION_ERROR,
    DECRYPTION_ERROR,
    FILE_NOT_FOUND_ERROR,
    INVALID_ENVIRONMENT_DIR,

    NO_FINGERPRINT_AVAILABLE,
    KEUGUARD_UNSECURE,
    REAUTHENTICATION_NEEDED,

    AUTH_ERROR,
    FINGERPRINT_INVALID,
    AUTH_HELP
    ;
}

package edu.uw.medhas.mhealthsecurityframework.password;

import java.util.regex.Pattern;

import edu.uw.medhas.mhealthsecurityframework.password.exception.PasswordNoLowerCaseCharacterException;
import edu.uw.medhas.mhealthsecurityframework.password.exception.PasswordNoNumberCharacterException;
import edu.uw.medhas.mhealthsecurityframework.password.exception.PasswordNoSpecialCharacterException;
import edu.uw.medhas.mhealthsecurityframework.password.exception.PasswordNoUpperCaseCharacterException;
import edu.uw.medhas.mhealthsecurityframework.password.exception.PasswordTooShortException;

/**
 * Created by medhas on 5/17/18.
 */
public class PasswordUtils {

    private static final Pattern mSpecialCharPattern = Pattern.compile("[^a-z0-9 ]",
            Pattern.CASE_INSENSITIVE);

    public static void validatePassword(String password) {
        boolean isAlphabetPresent = false;
        boolean isSpecialCharacterPresent = false;

        if (password.length() < 8) {
            throw new PasswordTooShortException();
        }

        // Check if password has upper case character
        if (password.equals(password.toLowerCase())) {
            throw new PasswordNoUpperCaseCharacterException();
        }

        // Check if password has upper case character
        if (password.equals(password.toUpperCase())) {
            throw new PasswordNoLowerCaseCharacterException();
        }

        // Check if password has number
        if (!password.matches(".*\\d+.*")) {
            throw new PasswordNoNumberCharacterException();
        }

        // Check if password has special character
        if (!mSpecialCharPattern.matcher(password).find()) {
            throw new PasswordNoSpecialCharacterException();
        }
    }
}

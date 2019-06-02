package edu.uw.medhas.mhealthsecurityframework.password.widget;

import android.content.Context;
import android.util.AttributeSet;
import android.support.v7.widget.AppCompatEditText;
import android.view.View;
import android.widget.Toast;

import edu.uw.medhas.mhealthsecurityframework.password.PasswordUtils;
import edu.uw.medhas.mhealthsecurityframework.password.exception.PasswordNoLowerCaseCharacterException;
import edu.uw.medhas.mhealthsecurityframework.password.exception.PasswordNoNumberCharacterException;
import edu.uw.medhas.mhealthsecurityframework.password.exception.PasswordNoSpecialCharacterException;
import edu.uw.medhas.mhealthsecurityframework.password.exception.PasswordNoUpperCaseCharacterException;
import edu.uw.medhas.mhealthsecurityframework.password.exception.PasswordTooShortException;

/**
 * Created by medhas on 10/20/18.
 */

public class PasswordEditText extends AppCompatEditText {
    public PasswordEditText(Context context) {
        super(context);
        setPasswordStrengthCheckListener();
    }

    public PasswordEditText(Context context, AttributeSet attrs) {
        super(context, attrs);
        setPasswordStrengthCheckListener();
    }

    public PasswordEditText(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        setPasswordStrengthCheckListener();
    }

    private void setPasswordStrengthCheckListener() {
        setOnFocusChangeListener(new OnFocusChangeListener() {
            @Override
            public void onFocusChange(View view, boolean focus) {
                if (!focus) {
                    final String passwordStr = getText().toString();
                    try {
                        PasswordUtils.validatePassword(passwordStr);
                        setError(null);
                    } catch (PasswordTooShortException ptsex) {
                        setError("Password is too small");
                    } catch (PasswordNoUpperCaseCharacterException pnuccex) {
                        setError("Password has no upper case character");
                    } catch (PasswordNoLowerCaseCharacterException pnlccex) {
                        setError("Password has no lower case character");
                    } catch (PasswordNoNumberCharacterException pnncex) {
                        setError("Password has no number");
                    } catch (PasswordNoSpecialCharacterException pnscex) {
                        setError("Password has no special character");
                    }

                }
            }
        });
    }
}

import totp

import time

fn test_new_and_check(){
    auth := totp.new()!
    code := auth.generate_totp(time.now().unix())!
    assert auth.check(code, 0)!
}

fn test_uri(){
    auth := totp.Authenticator{
        secret: 'JBSWY3DPEHPK3PXP'
        time_step: 30
        digits: 6
    }
    // Standard case
    uri := auth.generate_uri('Example', 'alice@site.com')
    expected := 'otpauth://totp/Example:alice%40site%2Ecom?secret=JBSWY3DPEHPK3PXP&issuer=Example&digits=6&algorithm=SHA1&period=30'
    assert uri == expected

    // Edge case: Special chars in issuer/account to test url_encode
    uri2 := auth.generate_uri('My & Company', 'bob smith')
    expected2 := 'otpauth://totp/My%20%26%20Company:bob%20smith?secret=JBSWY3DPEHPK3PXP&issuer=My+%26+Company&digits=6&algorithm=SHA1&period=30'
    assert uri2 == expected2

    // Custom digits/step
    auth3 := totp.Authenticator{
        secret: 'JBSWY3DPEHPK3PXP'
        time_step: 60
        digits: 8
    }
    uri3 := auth3.generate_uri('Test', 'user')
    expected3 := 'otpauth://totp/Test:user?secret=JBSWY3DPEHPK3PXP&issuer=Test&digits=8&algorithm=SHA1&period=60'
    assert uri3 == expected3
}
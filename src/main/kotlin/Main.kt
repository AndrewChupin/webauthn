import com.webauthn4j.WebAuthnManager
import com.webauthn4j.authenticator.AuthenticatorImpl
import com.webauthn4j.data.AuthenticationParameters
import com.webauthn4j.data.AuthenticationRequest
import com.webauthn4j.data.RegistrationRequest
import com.webauthn4j.data.client.Origin
import com.webauthn4j.data.client.challenge.DefaultChallenge
import com.webauthn4j.server.ServerProperty
import java.util.*


fun main() {
    val attestationObject = Base64.getUrlDecoder().decode("o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViUGnCEKvjB_rcTO4HmoWCmor5F7gV_DrbT9_USbaogLgddAAAAAAAAAAAAAAAAAAAAAAAAAAAAEEfzHQqW9OjJbBJSylNxtrulAQIDJiABIVgg1LgsFpV_rNv3QML-JYEG4nBvR8T9b0NercdmEuVKCTMiWCAQDAEGdM8hZ-z3MCZdidnXv5JPs0IBeyVBrniMpGvXew")

    val webAuthnManager = WebAuthnManager.createNonStrictWebAuthnManager()
    val registrationRequest = RegistrationRequest(attestationObject, null, null, setOf("internal", "hybrid"))
    val registrationData = webAuthnManager.parse(registrationRequest)
    val attestation = registrationData.attestationObject!!

    val authenticationRequest = AuthenticationRequest(
        Base64.getUrlDecoder().decode("R_MdCpb06MlsElLKU3G2uw"),
        Base64.getUrlDecoder().decode("SnVuZTQ"),
        Base64.getUrlDecoder().decode("GnCEKvjB_rcTO4HmoWCmor5F7gV_DrbT9_USbaogLgcdAAAAAA"),
        Base64.getUrlDecoder().decode("eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiWWFYOVAzUkhqSHpUS3dVc18tMXdaN1ZHUWw1ZHV2UlZBTmpRYkVnZExfSSIsIm9yaWdpbiI6ImFuZHJvaWQ6YXBrLWtleS1oYXNoOnRJalUwV2EzcC0xSWJldlA4WkVHYld4a05za0tHTzhKd1JodlRiTko1ZkUiLCJhbmRyb2lkUGFja2FnZU5hbWUiOiJjb20ud2FsbGV0LmNyeXB0by50cnVzdGFwcC5kZXYifQ"),
        null,
        Base64.getUrlDecoder().decode("MEUCIDeWJcGklyIhIc8boMFA4VcsIrfzIqs88wjp74-6KGFAAiEAttnxX2i26VUqtb9J-y0QmQwTBLwoVhKGdHapgTFNYvQ"),
    )

    val authResult = webAuthnManager.parse(authenticationRequest)
    val serverProperty = ServerProperty(
        Origin("android:apk-key-hash:tIjU0Wa3p-1IbevP8ZEGbWxkNskKGO8JwRhvTbNJ5fE"),
        "trustwallet.com",
        DefaultChallenge(Base64.getUrlDecoder().decode("YaX9P3RHjHzTKwUs_-1wZ7VGQl5duvRVANjQbEgdL_I")),
        byteArrayOf()
    )

    val authenticator = AuthenticatorImpl(
        attestation.authenticatorData.attestedCredentialData!!,
        attestation.attestationStatement,
        attestation.authenticatorData.signCount
    )

    val authenticationParameters = AuthenticationParameters(
        serverProperty,
        authenticator,
        null,
        true
    )

    webAuthnManager.validate(authResult, authenticationParameters)
    println("end")
}

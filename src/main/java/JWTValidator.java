import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;



class Main {
    public static void validateToken (HashMap<String, String> request) {
        Boolean auth = false;
        for (Map.Entry mapElement : request.entrySet()) {
            String key = (String)mapElement.getKey();
            if(key == Constants.AUTHORIZATION){
                HandleJWT(request);
                break;
            }
        }
    }

    public static void HandleJWT(HashMap<String, String> requestAttributes){
        String accessToken = requestAttributes.get(Constants.AUTHORIZATION);
        String[] tokenContent = accessToken.split("\\.");

        if(tokenContent.length != 3){
            System.out.println("Invalid JWT token received, token must have 3 parts");
        }
        String signedContent = tokenContent[0] + "." + tokenContent[1];
        //System.out.println(signedContent);
        boolean isVerified = validateSignature(accessToken, tokenContent[2]);
        if(isVerified){
            System.out.println("JWT Token is valid");
        } else {
            System.out.println("JWT Token is not valid");
        }
    }

    // validate the signature
    public static boolean validateSignature(String jwtToken, String signature){
        System.out.println("Inside validateSignature");
        JWSHeader header;
        JWTClaimsSet payload = null;
        SignedJWT parsedJWTToken;
        boolean isVerified = false;
        try{
            parsedJWTToken = (SignedJWT) JWTParser.parse(jwtToken);
            isVerified = verifyTokenSignature(parsedJWTToken);
        }catch (ParseException e) {
            System.out.println("Invalid JWT token. Failed to decode the token.");
        }
        return isVerified;
    }

    public static boolean verifyTokenSignature(SignedJWT parsedJWTToken) {
        RSAPublicKey publicKey = readPublicKey();
        Boolean state =false;
        if (publicKey != null){
            JWSAlgorithm algorithm = parsedJWTToken.getHeader().getAlgorithm();
            if (algorithm != null && (JWSAlgorithm.RS256.equals(algorithm) || JWSAlgorithm.RS512.equals(algorithm) ||
                    JWSAlgorithm.RS384.equals(algorithm))) {
                try{
                    JWSVerifier jwsVerifier = new RSASSAVerifier(publicKey);
                    state = parsedJWTToken.verify(jwsVerifier);
                    return state;
                } catch (JOSEException e) {
                    System.out.println(e);
                }
            }
        }
        return state;
    }

    public static RSAPublicKey readPublicKey() {
        RSAPublicKey publicKey = null;
        try {
            String strKeyPEM = "";
            BufferedReader br = new BufferedReader(new FileReader("./src/main/java/wso2carbon.pem"));
            String line;
            while ((line = br.readLine()) != null) {
                strKeyPEM += line + "\n";
            }
            br.close();
            //System.out.println(strKeyPEM);
            strKeyPEM = strKeyPEM.replace("-----BEGIN PUBLIC KEY-----\n", "");
            strKeyPEM = strKeyPEM.replaceAll(System.lineSeparator(), "");
            strKeyPEM = strKeyPEM.replace("-----END PUBLIC KEY-----", "");
            byte[] encoded = Base64.getDecoder().decode(strKeyPEM);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            RSAPublicKey pubKey = (RSAPublicKey) kf.generatePublic(new X509EncodedKeySpec(encoded));
            return pubKey;
        } catch (IOException | NoSuchAlgorithmException |InvalidKeySpecException e) {
            System.out.println(e);
        }
        return null;
    }

    public static void main(String[] args) {
        HashMap<String, String> request = new HashMap<String, String>();
        request.put(Constants.AUTHORIZATION, Constants.JWT_TOKEN);
        validateToken(request);
    }
}


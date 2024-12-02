package com.example.testt.jwt;

import java.nio.charset.StandardCharsets;
import java.util.Date;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Jwts;

@Component
public class JWTUtil {

    //RS방식 시크릿키
    //private PrivateKey privateSecretKey;
    private SecretKey secretKey;

    public JWTUtil(@Value("${spring.jwt.secret}") String secret) {
        this.secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), Jwts.SIG.HS256.key().build().getAlgorithm());
    }
    // public JWTUtil(@Value("${spring.jwt.secret}") String secret) {
    //     try {
    //         init();
    //     } catch (IOException | GeneralSecurityException e) {
    //         e.printStackTrace(); // 오류 출력
    //     }
    // }

    public String getUsername(String token) {
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("username", String.class);
    }

    public String getRole(String token) {
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("role", String.class);
    }

    public String getCategory(String token) {
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("category", String.class);
    }

    public Boolean isExpired(String token) {
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().getExpiration().before(new Date());
    }

    public String createJwt(String category, String username, String role, Long expiredMs) {
        return Jwts.builder()
                .claim("category", category)
                .claim("username", username)
                .claim("role", role) // 사용자 정보
                .issuedAt(new Date(System.currentTimeMillis())) //발행시간
                .expiration(new Date(System.currentTimeMillis() + expiredMs)) // 소멸시간(발행시간 + 시간)
                .signWith(secretKey) // 암호화
                .compact();
                
    }

    // //(RS)
    // public String createJwt(String username, String role, Long expiredMs, PrivateKey key) {
    //     return Jwts.builder()
    //             .claim("username", username)
    //             .claim("role", role)
    //             .issuedAt(new Date(System.currentTimeMillis())) //발행시간
    //             .expiration(new Date(System.currentTimeMillis() + expiredMs)) // 소멸시간(발행시간 + 시간)
    //             .signWith(key, SIG.RS256)
    //             .compact()
    //             ;

    // }

    // // 객체 초기화, 시크릿 키를 Base64로 인코딩 (RS)
    // protected void init() throws IOException, GeneralSecurityException {
    //     Path path = Paths.get("src/main/resources/private_key.pem");
    //     List<String> reads = Files.readAllLines(path);
    //     String read = String.join("\n", reads);
    //     // for(String str : reads){
    //     //     read += str+"\n";
    //     // } 위코드와 같음
        
    //     privateSecretKey = getPrivateKeyFromString(read);
    // }

    // //가지고있는 private_key.pem파일을 읽어서 Privatekey객체로 변환 (RS)
    // public static PrivateKey getPrivateKeyFromString(String pemString) throws IOException {
    //     PEMParser pemParser = new PEMParser(new StringReader(pemString)); // pemparser를 통해서 받은 pem파일의 값을 java객체로 변환
    //     Object object = pemParser.readObject();
    //     pemParser.close();

    //     // 컨버터를 사용해서 받은 객체를 PrivateKey로 변환할거임 여기서 BC는 그냥 라이브러리 이름임 (BouncyCastle)
    //     JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC"); 
    //     PrivateKey privateKey = null;

    //     if(object instanceof PrivateKeyInfo) { // 여기서 읽은 객체를 PrivateKeyInfo로 확인하고 컨버터로 PrivateKey객체로 변환중
    //         privateKey = converter.getPrivateKey((PrivateKeyInfo)object);
    //     }
    //     return privateKey; //PrivateKey를 반환함
    // }
}
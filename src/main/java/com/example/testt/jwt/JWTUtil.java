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


    // 로그아웃 버튼을 클릭시 구현할 기능을 통해 얻을 수 있는 이점은 JWT탈취 시간을 줄일 수 있다.
    // 프론트엔드 : 로컬 스토리지에 존재하는 Access 토큰 삭제 및 서버측 로그아웃 경로로 Refresh 토큰 전송
    // 백엔드 : 로그아웃 로직을 추가하여 Refresh 토큰을 받아 쿠키 초기화 후 Refresh DB에서 해당 Refresh 토큰 삭제
    // (모든 계정에서 로그아웃 구현시 username 기반으로 모든 Refresh 토큰 삭제) {JWT심화 9}


    // PC의 경우 IP주소가 변경될 일이 거의 없다. IP주소가 변경되는 경우 요청이 거부되도록 진행하면 더욱 보안이 강화된다.
    // 1. 로그인시 JWT발급과 함께 JWT와 IP를 DB에 저장
    // 2. Access 토큰으로 요청시 요청 IP와 로그인시 저장한 IP 주소를 대조
    // 3. Access 토큰 재발급시 새로운 Access 토큰과 IP를 DB에 저장

    // 네이버도 IP주소가 변경될 경우 다시 로그인을 하라는 알림이 나옴.

    /*
    1. 로그인을 하고 나서 access/refresh 토큰을 발행했습니다. 다음에 로그인 할때는 access 토큰으로 로그인해서 실패가 되면 fresh토큰을 이용해서 access 토큰과 refresh 토큰을 발행하고 다시 access 토큰을 통해서 로그인하는 것이 맞을가요?
    2. 처음 로그인을 하고나서 access 토큰을 발행하고 main화면으로 이동하려고 하는데 페이지 이동을 하게되면 header에 access 토큰을 실을 수가 없습니다.
    그럼 access token을 폼 데이터로 넘겨야 하나요? main 화면에서 Authentication authentication = SecurityContextHolder.getContext().getAuthentication();를 호출할 경우 null이 되거나 anonymousUser로 뜹니다.
    3. refresh 토큰을 RDB가 아닌 redis를 적용하여 강의를 해주실수 없으실가요?

    1.
    로그인 후 프론트앱(리액트와 같은 웹앱, 모바일앱, 등)으로 발급 받은 JWT(Access/Refresh) 중 기본적으로 대부분의 경로에 대해서 인증을 받아 데이터를 가져오기 위해서 Access JWT를 사용하게 됩니다.
    (로그인이라고 표현하신 부분이 인증 느낌입니다!)
    말씀하신대로 이때 Access JWT의 만료로 인증이 실패하는 경우 프론트측으로 인증 실패 응답이 돌아오고, 프론트측에선 실패 로직을 통해 Refresh JWT를 통해 백엔드의 /reissue 경로에 방문하여 새로운 JWT(Access/Refresh)를 발급 받으시면 됩니다!
    그 후 말씀하신대로 다시 Access JWT를 통해 인증을 진행하시면 됩니다.

    2.
    프론트측에서 username/password를 받은 후 API Client로 백엔드측에서 로그인 요청을 보내면 백엔드는 응답으로 JWT를 발급합니다.
    이때 프론트에서 발급 받은 JWT를 로컬스토리지와 같은 저장소에서 관리하셔야 합니다.
    이후 모든 요청에 대해서 로컬 스토리지에서 Access JWT를 꺼내어 요청 헤더에 붙여주는 작업을 프론트측에서 구현하셔야 백엔드에서 받으실 수 있습니다.

    3.
    이 부분도 댓글에 요청해 주신 분들이 계셨는데 현재 진행하고 있는 시리즈가 있어 이번 시리즈 끝나고 고민 해보도록 하겠습니다. (오래 걸릴거 같습니다...)
     */
}
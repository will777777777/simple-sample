package application.service;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;

import org.springframework.stereotype.Service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;

import application.model.Usuario;

@Service
public class TokenService {
    private String chaveJwt = "12345678";
    
    private Instant geraDataExpiracao() {
        return LocalDateTime.now().plusHours(2).toInstant(ZoneOffset.of("-03:00"));
    }
    
    public String generateToken(Usuario usuario) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(chaveJwt);
            return JWT.create()
                .withIssuer("TESTE_API")
                .withSubject(usuario.getNomeDeUsuario())
                .withExpiresAt(geraDataExpiracao())
                .sign(algorithm);
        } catch (JWTCreationException exception) {
            throw new RuntimeException("Erro ao gerar JWT");
        }
    }
    
    public String getSubject(String token) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(chaveJwt);
            return JWT.require(algorithm)
                .withIssuer("TESTE_API")
                .build()
                .verify(token)
                .getSubject();
        } catch (JWTVerificationException exception) {
            throw new RuntimeException("Token Inválido");
        }
    }
}
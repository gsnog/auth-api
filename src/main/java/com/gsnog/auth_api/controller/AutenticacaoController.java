package com.gsnog.auth_api.controller;

import com.gsnog.auth_api.dto.AutenticacaoDTO;
import com.gsnog.auth_api.dto.LoginResponseDTO;
import com.gsnog.auth_api.dto.RegistroDTO;
import com.gsnog.auth_api.model.Usuario;
import com.gsnog.auth_api.repository.UsuarioRepository;
import com.gsnog.auth_api.service.TokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AutenticacaoController {
    private final AuthenticationManager authenticationManager;
    private final TokenService tokenService;
    private final UsuarioRepository usuarioRepository;

    @PostMapping("/login")
    public ResponseEntity<LoginResponseDTO> login(@RequestBody AutenticacaoDTO autenticacaoDTO){
        UsernamePasswordAuthenticationToken usernamePAssword = new UsernamePasswordAuthenticationToken(autenticacaoDTO.email(), autenticacaoDTO.senha());
        Authentication auth = authenticationManager.authenticate(usernamePAssword);
        String token = tokenService.gerarToken((Usuario)auth.getPrincipal());
        return ResponseEntity.status(HttpStatus.OK).body(new LoginResponseDTO(token));
    }

    @PostMapping("/registrar")
    public ResponseEntity<Void> cadastro(@RequestBody RegistroDTO registroDTO){
        if (usuarioRepository.findByEmail(registroDTO.email()).isPresent()){
            return ResponseEntity.badRequest().build();
        }
        String senhaCriptografada = new BCryptPasswordEncoder().encode(registroDTO.senha());
        Usuario usuario = new Usuario();
        usuario.setEmail(registroDTO.email());
        usuario.setSenha(senhaCriptografada);
        usuarioRepository.save(usuario);
        return ResponseEntity.ok().build();
    }
}

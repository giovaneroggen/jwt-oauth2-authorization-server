# OAuth2 Authorization Server - JWT + Spring Boot

## Sobre o Projeto
Este projeto implementa um **Authorization Server OAuth2** usando Spring Boot com JWT, oferecendo autenticação e autorização segura para suas APIs. Ele é especialmente útil para sistemas que precisam:

- Proteger endpoints REST.
- Suportar múltiplos clientes e tipos de autenticação (Authorization Code, Client Credentials).
- Gerenciar usuários e roles de forma segura.

### Por que usar um Authorization Server?
Um Authorization Server centraliza a autenticação e a emissão de tokens JWT:

- Não é necessário gerenciar autenticação em cada serviço.
- Tokens JWT são auto-contidos, permitindo microservices independentes.
- Facilita o gerenciamento de escopos, roles e permissões.
- Compatível com padrões OAuth2/OpenID Connect.

## Configuração do Projeto
- **Spring Boot 3.5.6**
- **Spring Security** + OAuth2 Authorization Server
- **MongoDB** para armazenamento de usuários
- **JWK/JWT** para assinatura de tokens
- **Scopes**: `openid`, `api`

## Endpoints
- `/oauth2/authorize` - Endpoint de autorização (Authorization Code)
- `/oauth2/token` - Endpoint para obtenção de tokens JWT
- `/api/users` - Criar usuários (requer token com escopo `api` ou ROLE_ADMIN)

## Fluxo de Uso (cURL)

### 1️⃣ Authorization Code Flow
1. Obtenha o código de autorização:
```bash
http://localhost:8080/oauth2/authorize?response_type=code&client_id=client-id&scope=openid%20api&redirect_uri=http://localhost:8081/login/oauth2/code/client-id
```

2. Troque o código por JWT:
```bash
curl -X POST http://localhost:8080/oauth2/token \
  -u client-id:client-secret \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=SEU_AUTHORIZATION_CODE&redirect_uri=http://localhost:8081/login/oauth2/code/client-id"
```

### 2️⃣ Client Credentials Flow
```bash
curl -X POST http://localhost:8080/oauth2/token \
  -u client-id:client-secret \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&scope=api"
```

- O token retornado terá escopo `api` e pode ser usado para chamadas de API.

### 3️⃣ Criar usuário via API
```bash
curl -X POST http://localhost:8080/api/users \
  -H "Authorization: Bearer SEU_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
        "username": "newuser",
        "password": "123456",
        "roles": ["USER"]
      }'
```

> **Atenção:** Somente tokens com **escopo `api`** ou **ROLE_ADMIN** podem criar novos usuários.

## Conclusão
Com este Authorization Server você garante:
- Centralização da autenticação.
- Emissão segura de JWTs.
- Controle de acesso granular por escopo e roles.
- Compatibilidade com fluxos modernos OAuth2/OpenID Connect.

---

Spring Security + OAuth2: Segurança moderna e escalável para suas APIs.


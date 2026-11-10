from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
DATABASE = "ava.db"
SENHA_INICIAL = "Imperial@2026"

CORS(app, resources={r"/*": {"origins": [
    "https://avaimperial.netlify.app",
    "https://monumental-pothos-962d62.netlify.app"
]}})


def conectar():
    conexao = sqlite3.connect(DATABASE)
    conexao.row_factory = sqlite3.Row
    return conexao


def verificar_senha(hash_salvo, senha):
    if not hash_salvo:
        return False
    if hash_salvo.startswith(("$2a$", "$2b$", "$2y$")):
        try:
            import bcrypt
            return bcrypt.checkpw(senha.encode(), hash_salvo.encode())
        except Exception:
            return False
    try:
        return check_password_hash(hash_salvo, senha)
    except (ValueError, TypeError):
        return False


def email_institucional(nome):
    partes = nome.lower().split()
    return partes[0] + "." + partes[-1] + "@imperial.edu.br"


def criar_banco():
    conexao = conectar()
    conexao.execute("""
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT NOT NULL,
            email TEXT UNIQUE,
            senha_hash TEXT NOT NULL,
            tipo TEXT NOT NULL DEFAULT 'aluno'
                CHECK (tipo IN ('aluno', 'professor'))
        )
    """)
    colunas = {linha["name"] for linha in conexao.execute(
        "PRAGMA table_info(usuarios)"
    ).fetchall()}
    if "matricula" not in colunas:
        conexao.execute("ALTER TABLE usuarios ADD COLUMN matricula TEXT UNIQUE")
    if "curso" not in colunas:
        conexao.execute("ALTER TABLE usuarios ADD COLUMN curso TEXT")

    conexao.execute("""
        CREATE TABLE IF NOT EXISTS coordenadores (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            senha TEXT NOT NULL,
            curso TEXT NOT NULL,
            tipo_usuario TEXT NOT NULL DEFAULT 'coordenacao',
            criado_em DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    alunos = [
        "Ana Beatriz Nogueira", "Bruno Cardoso Menezes",
        "Camila Duarte Reis", "Diego Ferraz Alves",
        "Eduarda Prado Lima", "Felipe Rocha Torres",
        "Gabriela Nunes Souza", "Henrique Salles Braga"
    ]
    professores = [
        ("Marcos Vinícius Alves", "ENG101"),
        ("Helena Castro Nunes", "ENG203"),
        ("Roberto Ayres Lima", "MAT201"),
        ("Carla Menezes Braga", "EST104"),
        ("Fernanda Lopes Cardoso", "HUM110"),
        ("Thiago Santana Vieira", "GES100"),
        ("Yuri Batalha Silva", "FIS105")
    ]

    for nome, tipo, curso in (
        [(n, "aluno", None) for n in alunos] +
        [(n, "professor", c) for n, c in professores]
    ):
        email = email_institucional(nome)
        existente = conexao.execute(
            "SELECT id FROM usuarios WHERE lower(email)=lower(?)", (email,)
        ).fetchone()
        if existente:
            conexao.execute(
                "UPDATE usuarios SET tipo=?, curso=COALESCE(?, curso) WHERE id=?",
                (tipo, curso, existente["id"])
            )
        else:
            conexao.execute(
                "INSERT INTO usuarios (nome,email,senha_hash,tipo,curso) VALUES (?,?,?,?,?)",
                (nome, email, generate_password_hash(SENHA_INICIAL), tipo, curso)
            )

    coordenadora = conexao.execute(
        "SELECT id FROM coordenadores WHERE lower(email)=lower(?)",
        ("patricia.rocha@imperial.edu.br",)
    ).fetchone()
    if not coordenadora:
        conexao.execute("""
            INSERT INTO coordenadores (nome,email,senha,curso,tipo_usuario)
            VALUES (?,?,?,?,?)
        """, (
            "Patrícia Gomes Rocha",
            "patricia.rocha@imperial.edu.br",
            generate_password_hash(SENHA_INICIAL),
            "Não informado",
            "coordenacao"
        ))

    conexao.commit()
    conexao.close()


@app.get("/")
def inicio():
    return jsonify({"mensagem": "Backend do AVA Imperial funcionando!", "status": "online"})


@app.post("/login")
def login():
    dados = request.get_json(silent=True) or {}
    identificador = (
        dados.get("identificador") or dados.get("email") or
        dados.get("matricula") or ""
    ).strip()
    senha = dados.get("senha") or ""
    perfil = dados.get("perfil")

    if not identificador or not senha:
        return jsonify({"erro": "Informe seu e-mail ou matrícula e sua senha."}), 400

    conexao = conectar()
    usuario = conexao.execute("""
        SELECT id,nome,email,matricula,senha_hash,tipo,curso
        FROM usuarios
        WHERE lower(email)=lower(?) OR matricula=?
    """, (identificador, identificador)).fetchone()

    if usuario and verificar_senha(usuario["senha_hash"], senha):
        if perfil and usuario["tipo"] != perfil:
            conexao.close()
            return jsonify({"erro": "Este usuário não pertence ao perfil selecionado."}), 403
        resposta = {
            "id": usuario["id"], "nome": usuario["nome"],
            "email": usuario["email"], "matricula": usuario["matricula"],
            "tipo": usuario["tipo"], "curso": usuario["curso"]
        }
        conexao.close()
        return jsonify({"mensagem": "Login realizado com sucesso", "usuario": resposta}), 200

    coordenador = conexao.execute("""
        SELECT id,nome,email,senha,curso FROM coordenadores
        WHERE lower(email)=lower(?)
    """, (identificador,)).fetchone()

    if coordenador and verificar_senha(coordenador["senha"], senha):
        if perfil and perfil != "coordenacao":
            conexao.close()
            return jsonify({"erro": "Este usuário não pertence ao perfil selecionado."}), 403
        resposta = {
            "id": coordenador["id"], "nome": coordenador["nome"],
            "email": coordenador["email"], "matricula": None,
            "tipo": "coordenacao", "curso": coordenador["curso"]
        }
        conexao.close()
        return jsonify({"mensagem": "Login realizado com sucesso", "usuario": resposta}), 200

    conexao.close()
    return jsonify({"erro": "E-mail, matrícula ou senha inválidos."}), 401


criar_banco()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

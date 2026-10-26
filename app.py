
from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

app = Flask(__name__)
CORS(app, origins=[
    "https://monumental-pothos-962d62.netlify.app"
])
# Cria o banco de dados
def criar_banco():
    conexao = sqlite3.connect("ava.db")

    conexao.execute("""
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            senha_hash TEXT NOT NULL,
            tipo TEXT NOT NULL DEFAULT 'aluno'
                CHECK (tipo IN ('aluno', 'professor'))
        )
    """)

    conexao.commit()
    conexao.close()


# Rota inicial
@app.route("/")
def inicio():
    return "Backend do AVA funcionando!"


# Rota de cadastro
@app.route("/cadastro", methods=["POST"])
def cadastro():
    dados = request.get_json(silent=True) or {}

    nome = dados.get("nome", "").strip()
    email = dados.get("email", "").strip().lower()
    senha = dados.get("senha", "")

    if not nome or not email or not senha:
        return jsonify({
            "erro": "Preencha todos os campos"
        }), 400

    senha_hash = generate_password_hash(senha)

    try:
        conexao = sqlite3.connect("ava.db")

        conexao.execute(
            """
            INSERT INTO usuarios (nome, email, senha_hash)
            VALUES (?, ?, ?)
            """,
            (nome, email, senha_hash)
        )

        conexao.commit()
        conexao.close()

        return jsonify({
            "mensagem": "Usuário cadastrado com sucesso"
        }), 201

    except sqlite3.IntegrityError:
        return jsonify({
            "erro": "Este e-mail já está cadastrado"
        }), 409


# Rota de login
@app.route("/login", methods=["POST"])
def login():
    dados = request.get_json(silent=True) or {}

    email = dados.get("email", "").strip().lower()
    senha = dados.get("senha", "")

    if not email or not senha:
        return jsonify({
            "erro": "Informe e-mail e senha"
        }), 400

    conexao = sqlite3.connect("ava.db")
    conexao.row_factory = sqlite3.Row

    usuario = conexao.execute(
        """
        SELECT id, nome, email, senha_hash, tipo
        FROM usuarios
        WHERE email = ?
        """,
        (email,)
    ).fetchone()

    conexao.close()

    if usuario is None or not check_password_hash(
        usuario["senha_hash"], senha
    ):
        return jsonify({
            "erro": "E-mail ou senha inválidos"
        }), 401

    return jsonify({
        "mensagem": "Login realizado com sucesso",
        "usuario": {
            "id": usuario["id"],
            "nome": usuario["nome"],
            "email": usuario["email"],
            "tipo": usuario["tipo"]
        }
    }), 200


# Inicia o servidor
criar_banco()

if __name__ == "__main__":
    app.run(debug=True)
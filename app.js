import express from "express";
import mongoose from "mongoose";
import bcrypt from "bcrypt"; // Criptografar senha
import jwt from "jsonwebtoken"; // Criar e validar tokens JWT
import dotenv from "dotenv"; // Ambiente com arquivo .env

import User from "./models/usuarioModel.js";

dotenv.config(); // Carrega as variaveis de ambiente do arq. .ENV

const app = express();

app.use(express.json());

// Rota aberta
app.get("/", (req, res) => {
  res.status(200).json({ msg: "Bem vindo a nossa API! " });
});

// Rota privada
app.get("/user/:id", checktoken, async (req, res) => {
  const id = req.params.id;

  const user = await User.findById(id, "-password"); // Busca no banco o user sem a senha 

  if (!user) {
    return res.status(404).json({ msg: "Usuário não encontrado!" });
  }

  res.status(200).json({ user }); // Retorna os dados do user encontrado
});

function checktoken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) return res.status(401).json({ msg: "Acesso negado! " });

  try {
    const secret = process.env.SECRET;

    jwt.verify(token, secret);

    next();
  } catch (err) {
    res.status(400).json({ msg: "O token é inválido! " });
  }
  }
// Criação de usuarios
app.post("/auth/register", async (req, res) => {
  const { name, email, password, confirmpassword} = req.body;

  if (!name) {
    return res.status(422).json({ msg: "O nome é obrigatorio!"});
  }
  if (!email) {
    return res.status(422).json({ msg: "O email é obrigatorio!"});
  }
  if (!password) {
    return res.status(422).json({ msg: "A senha é obrigatorio!"});
  }
  if (password != confirmpassword) {
    return res
    .status(422)
    .json({msg: "A senha e a confirmação precisam ser iguais!"});
  }
  
  const userExists = await User.findOne({email: email});

  if (userExists){
    return res.status(422).json({msg: "Por favor, utilize outro e-mail!"})
  }

  const salt = await bcrypt.genSalt(12); // gera um salt para criptografar a senha 
  const passwordHash = await bcrypt.hash(password, salt); // Cria um hash da senha usando o salt

  const user = new User({
    name, 
    email,
    password: passwordHash,
  });

  try {
    await user.save(); // Salva o novo ususario no banco de dados

    res.status(201).json({msg: "Usuário criado com sucesso!"})
  } catch (error) {
    res.status(500).json({msg: error});
  }

});

app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email) {
    return res.status(422).json({ msg: "O email deve ser ser informado!"});
  }

  if (!password) {
    return res.status(422).json({ msg: "A senha deve ser informada!"});
  }

  const user = await User.findOne({ email: email}); //Busca o usuario no banco

  if (!user) {
    return res.status(404).json({ msg: "Usuário não encontrado! Por favor faça o cadastro."});
  }

  const checkPassword = await bcrypt.compare(password, user.password);

  if (!checkPassword) {
    return res.status(422).json({ msg: "Senha inválida, tente novamente"});
  }
// Fazer um env Secret para evitar invações
  try {
    const secret = process.env.SECRET;

    const token = jwt.sign(
      {
        id: user._id // Cria o token JWT contendo o ID do usuário
      },
      secret
    );
    res.status(200).json({ msg: "Autenticação realizada com sucesso!", token});
  } catch (error) {
    res.status(500).json({ msg: error}); // Somente se não gerar o token 
  }
});
// Credenciais
const dbUser = process.env.DB_USER;
const dbPassword = process.env.DB_PASS;

mongoose
  .connect(
    `mongodb+srv://${dbUser}:${dbPassword}@apiuc13-2.hpq3j.mongodb.net/?retryWrites=true&w=majority&appName=APIUC13-2`
  )
  .then(() => {
    app.listen(3000);
    console.log("Conectou ao Banco!");
  })
  .catch((err) => console.log(err));

// npm run start 
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
    passwordHash,
  });

  try {
    await user.save(); // Salva o novo ususario no banco de dados

    res.status(201).json({msg: "Usuário criado com sucesso!"})
  } catch (error) {
    res.status(500).json({msg: error});
  }

});
// Credenciais
const dbUser = process.env.DB_USER;
const dbPassword = process.env.DB_PASS;

mongoose
  .connect(
    `mongodb+srv://${dbUser}:${dbPassword}@api.hpq3j.mongodb.net/?retryWrites=true&w=majority&appName=API`
  
  )
  .then(() => {
    app.listen(3000);
    console.log("Conectou ao Banco!");
  })
  .catch((err) => console.log(err));

// npm run start
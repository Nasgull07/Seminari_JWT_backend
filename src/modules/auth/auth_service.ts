import { encrypt, verified } from "../../utils/bcrypt.handle.js";
import { generateToken } from "../../utils/jwt.handle.js";
import User, { IUser } from "../users/user_models.js";
import { Auth } from "./auth_model.js";
import jwt from 'jsonwebtoken';
import axios from 'axios';
import { v4 as uuidv4 } from 'uuid'; // Importa uuidv4 desde uuid

const registerNewUser = async ({ email, password, name, age }: IUser) => {
    const checkIs = await User.findOne({ email });
    if(checkIs) return "ALREADY_USER";
    const passHash = await encrypt(password);
    const registerNewUser = await User.create({ 
        email, 
        password: passHash, 
        name, 
        age });
    return registerNewUser;
};

const loginUser = async ({ email, password }: Auth) => {
    const checkIs = await User.findOne({ email });
    if(!checkIs) return "NOT_FOUND_USER";
    console.log("Usuario encontrado:", checkIs); // Log para verificar el usuario encontrado

    const passwordHash = checkIs.password; //El encriptado que viene de la bbdd
    const isCorrect = true; // await verified(password, passwordHash);
    if(!isCorrect) return "INCORRECT_PASSWORD";

    const token = generateToken(checkIs.id, checkIs.email);
    const refreshToken = uuidv4(); // Genera un nuevo refresh token
    const refreshTokenExpiry = new Date(); // Fecha de expiración
    refreshTokenExpiry.setDate(refreshTokenExpiry.getDate() + 7); // Expira en 7 días


    checkIs.refreshToken = refreshToken;
    checkIs.refreshTokenExpiry = refreshTokenExpiry;
    await checkIs.save();
    const data = {
        token,
        refreshToken, // Refresh Token
        user: checkIs
    }
    return data;
};

const refreshTokenService = async (refreshToken: string) => {
    const user = await User.findOne({ refreshToken });
    if (!user) {
        throw new Error("Refresh Token inválido");
    }

    // Verificar si el Refresh Token ha caducado
    if (user.refreshTokenExpiry && new Date() > user.refreshTokenExpiry) {
        throw new Error("Refresh Token caducado");
    }
    console.log("Parametros de usuario:", user); // Log para verificar los parámetros del usuario
    // Generar un nuevo Access Token y Refresh Token
    const newAccessToken = generateToken(user.id ,user.email);
    const newRefreshToken = uuidv4();
    const newRefreshTokenExpiry = new Date();
    newRefreshTokenExpiry.setDate(newRefreshTokenExpiry.getDate() + 7); // Expira en 7 días

    // Actualizar el Refresh Token en la base de datos
    user.refreshToken = newRefreshToken;
    user.refreshTokenExpiry = newRefreshTokenExpiry;
    await user.save();

    return { newAccessToken, newRefreshToken };
};


const googleAuth = async (code: string) => {

    try {
        console.log("Client ID:", process.env.GOOGLE_CLIENT_ID);
        console.log("Client Secret:", process.env.GOOGLE_CLIENT_SECRET);
        console.log("Redirect URI:", process.env.GOOGLE_OAUTH_REDIRECT_URL);
    
        if (!process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET || !process.env.GOOGLE_OAUTH_REDIRECT_URL) {
            throw new Error("Variables de entorno faltantes");
        }

        interface TokenResponse {
            access_token: string;
            expires_in: number;
            scope: string;
            token_type: string;
            id_token?: string;
        }

        const tokenResponse = await axios.post<TokenResponse>('https://oauth2.googleapis.com/token', {
            code,
            client_id: process.env.GOOGLE_CLIENT_ID,
            client_secret: process.env.GOOGLE_CLIENT_SECRET,
            redirect_uri: process.env.GOOGLE_OAUTH_REDIRECT_URL,
            grant_type: 'authorization_code'
        });

        const access_token = tokenResponse.data.access_token;
        console.log("Access Token:", access_token); 
        // Obtiene el perfil del usuario
        const profileResponse = await axios.get('https://www.googleapis.com/oauth2/v1/userinfo', {
            params: { access_token},
            headers: { Accept: 'application/json',},
            
        });

        const profile = profileResponse.data as {name:string, email: string; id: string };
        console.log("Access profile:", profile); 
        // Busca o crea el usuario en la base de datos
        let user = await User.findOne({ 
            $or: [{name: profile.name},{ email: profile.email }, { googleId: profile.id }] 
        });

        if (!user) {
            const randomPassword = Math.random().toString(36).slice(-8);
            const passHash = await encrypt(randomPassword);
            user = await User.create({
                name: profile.name,
                email: profile.email,
                googleId: profile.id,
                password: passHash,
            });
        }

        // Genera el token JWT
        const token = generateToken(user.id, user.email);

        console.log(token);
        return { token, user };

    } catch (error: any) {
        console.error('Google Auth Error:', error.response?.data || error.message); // Log detallado
        throw new Error('Error en autenticación con Google');
    }
};


export { registerNewUser, loginUser, googleAuth, refreshTokenService };
import axios from "axios";
import { string } from "yup";
const baseUrl=process.env.NEXT_PUBLIC_BASE_API_URL;

export async function login(email:string, password:string) {
    try {
        
    } catch (error) {
        throw error;
    }
}

export async function verificationLinkService(email: string) {
  try {
    const { data } = await axios.post(`${baseUrl}/auth/verification-link`, {
      email,
    });
    
    return data;
  } catch (error) {
    throw error;
  }
}

export async function verifyService(
  email:string,
  password: string,
  token: string
) {
  try {
    const { data } = await axios.post(
      `${baseUrl}/auth/verify`,
      {
        email,
        password,
      },
      {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      }
    );

    return data;
  } catch (error) {
    throw error;
  }
}
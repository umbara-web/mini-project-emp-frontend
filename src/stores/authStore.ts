import axios from "axios";
import {create} from "zustand";

const baseUrl=process.env.NEXT_PUBLIC_BASE_API_URL;

interface IAuthStore {
  email: string;
  isLoggedIn: boolean;
  role: string;
  
  onLogin: (email: string, role: string) => void;
  onLogout: () => void;
}

export async function loginService(email: string, password: string) {
  try {
    const { data } = await axios.post(`${baseUrl}/auth/login`, {
      email,
      password,
    });

    return data;
  } catch (err) {
    throw err;
  }
}

export async function refreshTokenService(token: string) {
  try {
    const { data } = await axios.post(`${baseUrl}/auth/refresh`, {
      token,
    });

    return data;
  } catch (err) {
    throw err;
  }
}

export async function verificationLinkService(email: string) {
  try {
    const { data } = await axios.post(`${baseUrl}/auth/verification-link`, {
      email,
    });

    return data;
  } catch (err) {
    throw err;
  }
}

export async function verifyService(
  firstname: string,
  lastname: string,
  password: string,
  token: string
) {
  try {
    const { data } = await axios.post(
      `${baseUrl}/auth/verify`,
      {
        firstname,
        lastname,
        password,
      },
      {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      }
    );

    return data;
  } catch (err) {
    throw err;
  }
}

const useAuthStore = create<IAuthStore>((set) => ({
  email: "",
  isLoggedIn: false,
  role: "",

  onLogin: (email: string, role: string) => {
    set(() => ({ isLoggedIn: true, email, role }));
  },
  onLogout: () => {
    set(() => ({ isLoggedIn: false, email: "", role: "" }));
  },
}));

export default useAuthStore;

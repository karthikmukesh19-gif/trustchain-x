import type { TokenResponse, User } from "../utils/types";
import { api } from "./api";

export async function login(email: string, password: string): Promise<TokenResponse> {
  const { data } = await api.post<TokenResponse>("/auth/login", { email, password });
  return data;
}

export async function register(fullName: string, email: string, password: string): Promise<TokenResponse> {
  const { data } = await api.post<TokenResponse>("/auth/register", {
    full_name: fullName,
    email,
    password,
  });
  return data;
}

export async function fetchCurrentUser(): Promise<User> {
  const { data } = await api.get<User>("/auth/me");
  return data;
}

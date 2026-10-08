import axios from "axios";

import type { Liveness, Readiness } from "../utils/types";
import { api } from "./api";

export async function getLiveness(): Promise<Liveness> {
  const { data } = await api.get<Liveness>("/health");
  return data;
}

/** Readiness answers 503 with the same body when MongoDB is down; that is still a result. */
export async function getReadiness(): Promise<Readiness> {
  try {
    const { data } = await api.get<Readiness>("/health/ready");
    return data;
  } catch (error) {
    if (axios.isAxiosError(error) && error.response?.status === 503 && error.response.data?.checks) {
      return error.response.data as Readiness;
    }
    throw error;
  }
}

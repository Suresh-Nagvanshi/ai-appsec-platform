import { api } from "@/lib/api";

export async function getFindings() {

const response = await api.get(
"/findings"
);

return response.data;
}

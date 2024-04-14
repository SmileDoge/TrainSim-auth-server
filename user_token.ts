import { JWTPayloadBase } from "./jwt";

export interface JWTUserPayload extends JWTPayloadBase
{
    name: string
}
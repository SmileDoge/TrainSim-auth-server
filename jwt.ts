import * as crypto from "crypto"
import express, { Request } from "express"

function base64encode(str) {
    return Buffer.from(str)
        .toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '')
}

function base64decode(str) {
    return Buffer.from(str, "base64").toString("utf-8")
}

function getBase64Json(object) {
    return base64encode(JSON.stringify(object))
}

export interface JWTTokenRequest extends Request
{
    jwt_payload: any
}

export interface JWTPayloadBase
{
    exp?: number
    iat?: number
}

export function getCurrentTime() : number {
    return Math.floor(Date.now() / 1000)
}

export function generateJWT(payload : any, key : string, alive_time : number) : string {
    let header = {"alg": "HS256", "typ": "JWT"}

    let hmac = crypto.createHmac("SHA256", key)

    payload.iat = getCurrentTime()
    payload.exp = payload.iat + alive_time

    let header_data = getBase64Json(header)
    let payload_data = getBase64Json(payload)

    let data = hmac.update(header_data + "." + payload_data)

    let sign = data.digest("base64url")

    return header_data + "." + payload_data+ "." + sign
}

export function verifyJWT(jwt: string, key : string) : boolean {
    let parts = jwt.split(".")

    if (parts.length != 3) return false

    let header_data = parts[0]
    let payload_data = parts[1]
    let sign = parts[2]

    let hmac = crypto.createHmac("SHA256", key)

    let data = hmac.update(header_data + "." + payload_data)

    let new_sign = data.digest("base64url")

    if (sign !== new_sign)
        return false

    let payload = extractPayloadJWT(jwt)

    let current_time = getCurrentTime()

    if (current_time > payload.exp)
        return false

    return true
}

export function extractPayloadJWT(jwt : string) : JWTPayloadBase {
    if (!jwt || jwt == "") return null

    let parts = jwt.split(".")

    if (parts.length != 3) return null

    try {
        return JSON.parse(base64decode(parts[1]))
    } catch (err) {
        return null
    }
}

export function getJWTRouter(key: string) : express.Router {
    let router = express.Router()

    router.use((req: JWTTokenRequest, res, next) => {
        let auth_header = req.header("authorization")
    
        if (!auth_header)
            return next()
    
        let bearer_auth = auth_header.split(" ")
    
        if (bearer_auth.length != 2)
            return next()
    
        let jwt_auth = bearer_auth[1]
    
        let jwt_payload = extractPayloadJWT(jwt_auth)
    
        if (!verifyJWT(jwt_auth, key))
            return next()
    
        req.jwt_payload = jwt_payload
    
        next()
    })

    return router
}

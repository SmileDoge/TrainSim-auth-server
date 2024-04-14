import express from "express"
import { JWTTokenRequest, extractPayloadJWT, generateJWT, verifyJWT } from "./jwt"
import { config } from "./config"
import { JWTUserPayload } from "./user_token"

interface ConnectTokenRequest
{
    user_token: string
    nickname?: string
}

function checkBodyValid(body: ConnectTokenRequest) : boolean {
    //if (!body.user_token) return false

    return true
}

export function getConnectTokenRouter() {
    let router = express.Router()

    router.get("/verify-connect-token", (req: JWTTokenRequest, res) => {
        let is_valid = false
    
        let data = {}
    
        if (req.jwt_payload) {
            is_valid = true
    
            data = {
                "nickname": req.jwt_payload.name
            }
        }
    
        res.json({
            "is_valid": is_valid,
            "data": data
        })
    })
    
    router.post("/get-connect-token", (req: JWTTokenRequest, res) => {
        if (!checkBodyValid(req.body)) return res.status(400).send({"error": true})
    
        let connect_body: ConnectTokenRequest = req.body
        
        //if (!verifyJWT(connect_body.user_token, config.jwt_secret_key)) return res.status(403).send({"error": true})

        let payload_jwt = <JWTUserPayload> extractPayloadJWT(connect_body.user_token)

        let nickname: string = connect_body.nickname ?? payload_jwt.name

        nickname = nickname.substring(0, 32)
    
        let payload = {
            "name": nickname
        }
    
        let result = {
            "token": generateJWT(payload, config.jwt_secret_key, config.connect_token_live_time)
        }
    
        res.send(result)
    })

    return router
}
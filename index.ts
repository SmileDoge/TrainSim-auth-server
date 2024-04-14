import express from "express"

import { getJWTRouter } from "./jwt"
import { config } from "./config"
import { getConnectTokenRouter } from "./connect_token"

const app = express()

app.use(express.json())

app.use(getJWTRouter(config.jwt_secret_key))

app.use(getConnectTokenRouter())

app.listen(1337, () => {
    console.log("Listening")
})

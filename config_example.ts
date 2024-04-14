export interface Config {
    jwt_secret_key: string

    connect_token_live_time: number
}

export var config: Config = {
    jwt_secret_key: "example_secret",
    connect_token_live_time: 15
}
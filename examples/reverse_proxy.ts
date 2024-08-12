import { IConfig, IModulesCaddyhttpReverseproxyHandler } from '../index'

const config: IConfig = {
    apps: {
        http: {
            servers: {
                app: {
                    routes: [
                        {
                            handler: "reverse_proxy",
                            headers: {
                                handler: "headers",
                                request: {
                                    set: {
                                        "Host": [
                                            "{http.reverse_proxy.upstream.hostport}"
                                        ]
                                    }
                                }
                            },
                            transport: {
                                "protocol": "http",
                                "tls": {}
                            },
                            upstreams: [
                                {
                                    "dial": "www.somewhere.com:443"
                                }
                            ]
                        } as IModulesCaddyhttpReverseproxyHandler
                    ]
                }
            }
        }
    }
}
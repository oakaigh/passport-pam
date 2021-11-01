import * as dns from 'dns';
import * as pam from 'node-linux-pam';
import * as express from 'express';
import * as passport_local from 'passport-local';
import * as passport_http from 'passport-http';


export interface IStrategyOptions {
    serviceName: string;
    resolve?: boolean | false;
}

export interface VerifyFunction {
    (
        req: express.Request,
        username: string,
        password: string,
        authenticated: boolean,
        done: (error: any, user?: any, options?: any) => void
    ): void;
}

export function Strategy(
    BaseStrategy:
        (typeof passport_local.Strategy)
        | (typeof passport_http.BasicStrategy)
): any {
    return class extends BaseStrategy {
        constructor(
            base_options:
                passport_local.IStrategyOptionsWithRequest
                | passport_http.BasicStrategyOptions,
            options: IStrategyOptions,
            verify: VerifyFunction
        ) {
            super(
                {
                    ...base_options,
                    passReqToCallback: true
                },
                async (req, username, password, done) => {
                    class AuthSuccess extends Error {};

                    const authenticate = async (
                        username: string,
                        password: string,
                        service: string,
                        hostnames: string[],
                        error?: (err: pam.PamError) => any | undefined
                    ) => {
                        var res = false;

                        var promises = [];
                        for (const hostname of hostnames) {
                            promises.push(
                                pam.pamAuthenticatePromise({
                                    username: username,
                                    password: password,
                                    serviceName: service,
                                    remoteHost: hostname
                                })
                                .then(() => {
                                    throw new AuthSuccess();
                                })
                                .catch((err) => {
                                    if (err instanceof pam.PamError) {
                                        if (error)
                                            error(err);
                                    } else {
                                        throw err;
                                    }
                                })
                            );
                        }

                        await Promise.all(promises).catch((err) => {
                            if (err instanceof AuthSuccess) {
                                res = true;
                            }
                        });
                        return res;
                    };

                    var hostnames = [];
                    var addr = req.socket.remoteAddress;
                    if (options.resolve)
                        hostnames.push(await dns.promises.reverse(addr));
                    hostnames.push(addr);

                    return verify(
                        req,
                        username,
                        password,
                        await authenticate(
                            username,
                            password,
                            options.serviceName,
                            hostnames
                        ),
                        done
                    );
                }
            );
        }
    };
}
